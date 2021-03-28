# frozen_string_literal: true

# config.ru
require 'opentelemetry/sdk'
require 'opentelemetry-instrumentation-all'
require 'opentelemetry-exporter-otlp'
require 'opentelemetry/exporter/jaeger'
require 'lightstep'
require 'opentracing'

require 'rack/protection'
require './app'


#### BEGIN OPENTELEMETRY INSTRUMENTATION #####

# OpenTelemetry::SDK.configure do |c|
#   c.service_name = "sandbox_test_ruby"
#   c.use 'OpenTelemetry::Instrumentation::Rack'
#   c.use 'OpenTelemetry::Instrumentation::Sinatra'
#   c.use 'OpenTelemetry::Instrumentation::Faraday'
#   c.use 'OpenTelemetry::Instrumentation::Redis'

#   c.add_span_processor(
#     OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(
#       # for the jaeger exporter:
#       # exporter: 
#       OpenTelemetry::Exporter::Jaeger::CollectorExporter.new()
#       # OpenTelemetry::Exporter::Zipkin::Exporter.new(endpoint: 'http://localhost:9411/api/v2/spans')
#       # OpenTelemetry::Exporter::Zipkin::Exporter.new(endpoint: 'http://otel-collector:9411/api/v2/spans')
#       # exporter: OpenTelemetry::Exporter::Zipkin::Exporter.new()
#     )
    
#   )
# end

#### END OPENTELEMETRY INSTRUMENTATION #####

#### START OPENTRACING / LS / DATADOG-AGENT TRANSPORT EXPORT INSTRUMENTATION #####


require 'net/http'

module ExampleDatadog
  module Transport
    # HTTPJSON is a transport that sends reports via HTTP in JSON format.
    # It is thread-safe.
    class HTTPJSON < ::LightStep::Transport::Base
      LIGHTSTEP_HOST = ENV.fetch('OTEL_EXPORTER_DATADOG_ENDPOINT', "otel-collector")
      LIGHTSTEP_PORT = 8126

      ENCRYPTION_TLS = 'tls'.freeze
      ENCRYPTION_NONE = 'none'.freeze

      REPORTS_API_ENDPOINT = '/v0.3/traces'.freeze
      HEADER_ACCESS_TOKEN = 'LightStep-Access-Token'.freeze

      ##
      # Initialize the transport
      #
      # @param host [String] host of the domain to the endpoint to push data
      # @param port [Numeric] port on which to connect
      # @param verbose [Numeric] verbosity level. Right now 0-3 are supported
      # @param encryption [ENCRYPTION_TLS, ENCRYPTION_NONE] kind of encryption to use
      # @param access_token [String] access token for LightStep server
      # @param ssl_verify_peer [Boolean]
      # @param open_timeout [Integer]
      # @param read_timeout [Integer]
      # @param continue_timeout [Integer]
      # @param keep_alive_timeout [Integer]
      # @param logger [Logger]
      #
      def initialize(
        host: ENV.fetch('OTEL_EXPORTER_DATADOG_ENDPOINT', "otel-collector"),
        port: LIGHTSTEP_PORT,
        verbose: 0,
        encryption: ENCRYPTION_NONE,
        access_token: 'custom',
        ssl_verify_peer: false,
        open_timeout: 20,
        read_timeout: 20,
        continue_timeout: nil,
        keep_alive_timeout: 2,
        logger: nil
      )
        @host = host
        @port = port
        @verbose = verbose
        @encryption = encryption
        @ssl_verify_peer = ssl_verify_peer
        @open_timeout = open_timeout.to_i
        @read_timeout = read_timeout.to_i
        @continue_timeout = continue_timeout
        @keep_alive_timeout = keep_alive_timeout.to_i

        raise Tracer::ConfigurationError, 'access_token must be a string' unless access_token.is_a?(String)
        raise Tracer::ConfigurationError, 'access_token cannot be blank'  if access_token.empty?
        @access_token = access_token
        @logger = logger || LightStep.logger
      end

      ##
      # Queue a report for sending
      #
      def report(report)
        @logger.info report if @verbose >= 3

        req = build_request(report)
        res = connection.request(req)

        @logger.info res.to_s if @verbose >= 3

        nil
      end

      private

      ##
      # @param [Hash] report
      # @return [Net::HTTP::Post]
      #
      def build_request(report)
        req = Net::HTTP::Post.new(REPORTS_API_ENDPOINT)
        req[HEADER_ACCESS_TOKEN] = @access_token
        req['Content-Type'] = 'application/json'
        # dd-trace-rb does not use keep alive
        # from: https://github.com/DataDog/dd-trace-rb/blob/master/lib/ddtrace/transport/http/adapters/net.rb
        # req['Connection'] = 'keep-alive'

        # TODO: implement other headers
        # https://github.com/DataDog/dd-trace-rb/blob/000e16777a813fad44b4c8aed02dc557df6aefa3/lib/ddtrace/transport/http.rb#L68
        req.body = translate_to_datadog(report[:span_records], report[:runtime]).to_json
        req
      end

      ##
      # @return [Net::HTTP]
      #
      def connection
        unless @connection
          @connection = ::Net::HTTP.new(@host, @port)
          @connection.use_ssl = @encryption == ENCRYPTION_TLS
          @connection.verify_mode = ::OpenSSL::SSL::VERIFY_NONE unless @ssl_verify_peer
          @connection.open_timeout = @open_timeout
          @connection.read_timeout = @read_timeout

          # not implemented in dd-trace-rb
          # from: https://github.com/DataDog/dd-trace-rb/blob/master/lib/ddtrace/transport/http/adapters/net.rb
          # @connection.continue_timeout = @continue_timeout
          # @connection.keep_alive_timeout = @keep_alive_timeout
        end
        @connection
      end

      ##
      # translate lightstep spans to datadog spans
      # using proto from: https://github.com/DataDog/datadog-agent/blob/49f5b4d188d73887b942b59f59708ab32091bbb4/pkg/trace/pb/span.proto
      # @param [Array] span_records
      # @return [Array] 
      def translate_to_datadog(ls_span_array, runtime_tags)
        global_attributes = runtime_tags[:attrs].each_with_object({}) do |global_attr, tags|
          tags[global_attr[:Key]] = global_attr[:Value]
        end

        traces_hash = ls_span_array.each_with_object({}) do |ls_span, traces|
          attributes = ls_span[:attributes].each_with_object({}) do |attribute, attrs|
            attrs[attribute[:Key]] = attribute[:Value]    # storing key => value pairs in the hash
          end
 
          attributes = attributes.merge(global_attributes)

          dd_span = {
            trace_id: ls_span[:trace_guid].to_i(16),
            span_id: ls_span[:span_guid].to_i(16),
            name: ls_span[:span_name],
            resource: ls_span[:span_name],
            start: ls_span[:oldest_micros] * 1000,
            duration: (ls_span[:youngest_micros] - ls_span[:oldest_micros]) * 1000,
            error: (ls_span[:error_flag] || attributes[:error]) ? 1 : 0,
            meta: attributes,
            metrics: {},
            type: attributes['span.kind'] && (attributes['span.kind'] == 'client' || attributes['span.kind'] == 'server') ? "web" : "custom"
          }

          dd_span[:parent_id] = attributes[:parent_span_guid].to_i(16) if attributes && attributes.key?(:parent_span_guid) 
          dd_span[:service] = (attributes["service.name"] if attributes && attributes.key?("service.name")) || runtime_tags[:group_name] 

          if traces.key?(dd_span[:trace_id])
            traces[dd_span[:trace_id]] << dd_span
          else
            traces[dd_span[:trace_id]] = [dd_span]
          end
        end

        traces_hash.values
      end
    end
  end
end

tracer = LightStep::Tracer.new(component_name: "YOUR_SERVICE_NAME", propagator: :b3, tags: {env: 'sandbox', version: 'v1', 'service.name': "sinatra-service"}, transport: ExampleDatadog::Transport::HTTPJSON.new())
OpenTracing.global_tracer = tracer

#### END OPENTRACING / LS / DATADOG-AGENT TRANSPORT EXPORT INSTRUMENTATION #####

run Multivac

