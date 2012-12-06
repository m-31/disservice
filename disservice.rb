#!/usr/bin/env ruby

#
#  Copyright © 2012 Matthias Bauer <http://matthias-bauer.net/>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

require 'optparse'
require 'socket'
require 'digest/sha1'
require 'benchmark'
require 'fileutils'
require 'find'

module Disservice
  VERSION = '0.3.2'

  class Disservice
    def initialize(options)
      if options[:daemonize]
        logfile = [$0.sub(/\.rb$/, ''), options[:port], options[:dsthost], options[:dstport]].join('_') << '.log'
        Process.daemon(true, true)
        $stderr.puts "running in the background (pid: #{$$}), logfile: #{logfile}"
        File.open($0 + '.pid', 'w'){ |f| f.write($$) }
        STDIN.reopen "/dev/null"
        STDOUT.reopen logfile, "a"
        STDERR.reopen logfile, "a"
      end
      if options[:log] != '-'
        STDOUT.reopen options[:log], "a"
        STDERR.reopen options[:log], "a"
      end

      Logger.level = options[:loglevel]
      Logger.info "#{$0} #{VERSION} starting up"
      Logger.debug "options: #{options.inspect}"

      @options = options

      @mocker = Mocker.new(options[:mocks_dir])
      @server = Server.new(options[:port], options[:dsthost], options[:dstport], @mocker, @options)
    end

    def run_server
      Logger.debug "running server"
      @server.run
    end
  end


  class Logger
    def self.level=(level)
      @@log_level = level
    end

    def self.method_missing(fn, a)
      @@log_level ||= 'info'
      @@levels = %w(debug info warn error)
      return if @@levels.index(fn.to_s) < @@levels.index(@@log_level)
      return unless a
      a = a.inspect unless a.is_a? String
      @@mutex ||= Mutex.new
      @@mutex.synchronize {
        a.lines.each_with_index do |line, idx|
          line = '  ' << line if idx > 0
          $stderr.puts "[%s] (%s) %s" % [Time.now, fn, line]
        end
      }
    end
  end


  class Mocker
    attr_accessor :ignore_headers

    def initialize(mocks_dir)
      mocks_dir << '/' unless mocks_dir =~ /\/$/

      @mocks_dir = mocks_dir

      @request_map = {}
      @not_persisted = []
      @ignore_headers = []

      Logger.info "reading mocks from #{mocks_dir}"
      Find.find(@mocks_dir).select{ |fn| File.file?(fn) && File.basename(fn)[0] != '.' }.each do |fn|
        s = File.open(fn, 'rb'){ |f| f.read }
        request_line = s.lines.first
        request_body = nil
        if request_line =~ /^POST|^PUT/
          request, request_body, response = s.split(/\r?\n\r?\n/, 3)
          request = [request, request_body].join("\r\n\r\n")
        else
          request, response = s.split(/\r?\n\r?\n/, 2)
        end
        add(request, response, {fn: fn})
        Logger.debug '  ' << fn << ' => ' << request_line
      end
    end

    def match(request)
      request_line, request_headers = request.split(/\r\n/, 2)
      request_headers_map = Hash[request_headers.split(/\r?\n/)[1..-1].map{ |l| l.split(/: /, 2) }]
      host = request_headers_map['Host'] rescue 'NO-HOST'
      v = @request_map[host][request_line] rescue nil
      return v if v.nil?

      stored_headers, stored_body = v[:request].split(/(\r?\n){2}/, 2)
      stored_headers_map = Hash[stored_headers[1..-1].split(/\r?\n/)[1..-1].map{ |l| l.split(/: /, 2) }]
      Logger.debug "request line: #{request_line.inspect}"
      Logger.debug "request headers: #{request_headers_map.inspect}"
      Logger.debug "stored headers: #{stored_headers_map.inspect}"
      headers_matched = request_headers_map.all? do |k,v|
        true and next if @ignore_headers.include?(k)
        #Logger.debug "matching header #{k.inspect}: #{v.inspect} against #{stored_headers_map.fetch(k, nil).inspect}"
        !stored_headers_map.has_key?(k) || File.fnmatch(v, stored_headers_map[k])
      end
      Logger.debug "headers matched? #{headers_matched.inspect}"
      return v if headers_matched

      nil
    end

    def store(request, response)
      request_line, _ = request.split(/\r?\n/, 2)
      if match(request)
        Logger.debug "not storing already known request: \"#{request_line}\""
      else
        Logger.debug "storing new request: \"#{request_line}\""
        add(request, response, {fn: '-'})
        @not_persisted.push(request)
        Thread.new do
          sleep 5
          save
        end
      end
    end

    def save
      return if @not_persisted.size == 0
      Logger.debug "saving #{@not_persisted.size} entries"
      @save_mutex ||= Mutex.new
      @save_mutex.synchronize do
        @not_persisted.each do |request|
          header, body = request.split(/(?:\r?\n){2}/, 2)
          request_line = header.lines.first.strip
          host = header.lines.find{ |x| x =~ /^Host: (.*)/ } || ''
          host = host.strip.split(/: /, 2).last.gsub(/:/, '_') rescue 'NO-HOST'
          verb = request_line[/^\w+/]
          url = request_line[/^\w+\s+(\S+)/, 1]
          version = request_line[/HTTP\/(1\.\d)\s*$/, 1]
          h = Digest::SHA1.hexdigest(header)[0..7]

          fn = [host, verb, [url.gsub(/\?.*/, '').gsub(/[\s:+*#]/, '_').gsub(/[\/\\?]/, '-')[0..128], h, version].join('_')].join('/')
          FileUtils.mkdir_p(@mocks_dir + [host, verb].join('/'))

          @request_map[host][request_line][:fn] = @mocks_dir + fn
          Logger.debug "persisting \"#{request_line}\" to #{@mocks_dir + fn}"
          value = @request_map[host][request_line]
          File.open(@mocks_dir + fn, 'wb') do |f|
            f.write(request)
            f.write("\r\n\r\n")
            f.write(value[:response])
          end
        end
        @not_persisted = []
      end
    end

    private
    def add(request, response, options={})
      request_line = request.lines.first.strip
      request.lines.find{ |x| x =~ /^Host: (.*)$/ }
      host = $1.strip rescue 'NO-HOST'
      @request_map[host] ||= {}
      @request_map[host][request_line] = options.merge({request: request, response: response})
      # @request_map[request_line] = options.merge({request: request, response: response})
    end
  end


  class Server
    def initialize(port, dsthost, dstport, mocker, options) # XXX options and handling should be factored out to a Handler
      @port = port
      @dsthost = dsthost
      @dstport = dstport
      @mocker = mocker
      @options = options

      @connection_count = 1
      @backlog = 1024

      @num_hits = 0
      @num_error = 0
    end

    def run
      begin
        @socket = TCPServer.new(@port)
        @socket.listen(@backlog)
        Signal.trap('USR1') do
          Logger.info "#{@connection_count-1} requests, #{@num_hits} cache hits, #{@num_hits.to_f/(@connection_count-1).to_f*100.0}% cache hit rate. #{@num_error} socket errors."
        end
        Logger.info "Listening on #{@port} (backlog #{@backlog})..."
        loop do
          Thread.start(@connection_count, @socket.accept, &method(:accept_request))
          @connection_count += 1
        end
      rescue Interrupt
        Logger.info 'Caught interrupt!'
      ensure
        if @socket
          Logger.info 'Closing sockets.'
          @socket.close
        end
        @mocker.save
        Logger.info "#{@connection_count-1} requests, #{@num_hits} cache hits, #{@num_hits.to_f/(@connection_count-1).to_f*100.0}% cache hit rate. #{@num_error} socket errors."
        Logger.info 'Exiting.'
      end
    end

    def accept_request(connection_count, to_client)
      begin
        _, peerport, peeraddr = to_client.peeraddr

        Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Reading client request"

        request = ''
        request_headers = ''
        request_body = ''
        response = ''

        request_line = to_client.readline

        verb = request_line[/^\w+/]
        url = request_line[/^\w+\s+(\S+)/, 1]
        version = request_line[/HTTP\/(1\.\d)\s*$/, 1]
        content_length = nil

        loop do
          line = to_client.readline
          
          case line
          when /^Connection: /
            # pass
          when /^Host: /
            request_headers << "Host: #{@dsthost}\r\n"
          else
            request_headers << line
          end

          if line =~ /^Content-Length: (\d+)/i
            content_length = $1.to_i
          end

          break if line.strip.empty?
        end
        if content_length && %w(POST PUT).include?(verb)
          line = to_client.read(content_length)
          request_body << line
        end
        request_headers_map = Hash[request_headers.split(/\r?\n/)[1..-1].map{ |l| l.split(/: /, 2) }]
        request_headers_map['Host'] = @dsthost

        request = request_line + request_headers
        request << request_body if request_body

        matched_request = @mocker.match(request) if @options[:known] == 'replay'

        if matched_request
          @num_hits += 1
          response = matched_request[:response]
          Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Request matched, sending response"
          to_client.write(response)
          Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Response written, closing connection"
          to_client.close
          Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Connection closed"
          upstream_response_time = '-'
        else
          Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Request NOT matched"
          # unknown request
          raise Exception if @options[:unknown] == 'croak' && !matched_request

          request_headers = request_headers_map.map{ |k,v| [k,v].join(': ') }.join("\r\n")

          upstream_response_time = sprintf('%.5f', Benchmark.realtime {
            Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Sending upstream request"
            to_server = TCPSocket.new(@dsthost, @dstport || 80)
            to_server.write(request_line)
            to_server.write("Connection: close\r\n")
            to_server.write(request_headers)
            to_server.write("\r\n\r\n")
            to_server.write(request_body)

            buff = ""
            Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Writing out upstream response"
            loop do
              to_server.read(4096, buff)
              to_client.write(buff)
              response << buff
              break if buff.size < 4096
            end

            to_client.close
            to_server.close
            Logger.debug "#{connection_count}: [#{peeraddr}:#{peerport}] Finished"
          })

          if @options[:unknown] == 'record' && !matched_request
            case @options[:record]
            when 'full'
              @mocker.store(request, response)
            when 'minimal'
              @mocker.store([request.lines.first, request.lines.find{ |x| x=~/^Host: / }].join(''), response)
            end
          end
        end
        Logger.info "##{connection_count}: [#{peeraddr}:#{peerport}] \"#{request_headers_map['Host']}\" \"#{request_line.strip}\" \"#{matched_request ? matched_request[:fn] : '-'}\" \"#{matched_request ? matched_request[:request].lines.first.strip : '-'}\" #{upstream_response_time}"
      rescue EOFError => e
        @num_error += 1
        Logger.warn "##{connection_count}: [#{peeraddr}:#{peerport}] EOF while reading from socket"
      rescue Errno::ECONNRESET, Errno::EPIPE => e
        @num_error += 1
        Logger.warn "##{connection_count}: [#{peeraddr}:#{peerport}] Connection error: #{e}"
      rescue SocketError => e
        @num_error += 1
        Logger.error "##{connection_count}: [#{peeraddr}:#{peerport}] Socket error: #{e}"
      end
    end
  end

end

options = {}
OptionParser.new do |opts|
  options[:known] = 'replay'
  opts.on('--known MODE', String, %w(pass replay), "What to do with 'known' (matched) requests (default: #{options[:known]})", "  pass: pass request/response unchanged", "  replay: return stored response") do |mode|
    options[:known] = mode
  end

  options[:unknown] = 'record'
  opts.on('--unknown MODE', String, %w(pass record croak), "What to do with 'unknown' (unmatched) requests (default: #{options[:unknown]})", "  pass: pass request/response unchanged", "  record: pass request upstream and store it", "  croak: throw an exception") do |mode|
    options[:unknown] = mode
  end

  options[:record] = 'full'
  opts.on('--record MODE', String, %w(full minimal), "How much of the request to record (default: #{options[:record]})", "  full: Full request w/ request headers", "  minimal: Only request-line and Host header") do |mode|
    options[:record] = mode
  end

  options[:mocks_dir] = './mocks/'
  opts.on('-m', '--mocks DIRECTORY', String, "Read recorded requests from DIRECTORY (default: #{options[:mocks_dir]})")

  options[:port] = 80
  opts.on('-l', '--listen PORT', Integer, "Listen on port PORT (default: #{options[:port]})") do |port|
    options[:port] = port
  end

  options[:dsthost] = 'localhost'
  opts.on('-d', '--dsthost DSTHOST', String, "Destination host to forward requests to (default: #{options[:dsthost]})") do |dsthost|
    options[:dsthost] = dsthost
  end

  options[:dstport] = '8080'
  opts.on('-p', '--dstport DSTPORT', Integer, "Destination port to forward requests to (default: #{options[:dstport]})") do |dstport|
    options[:dstport] = dstport
  end

  options[:log] = '-'
  opts.on('--log LOGFILE', String, "Write log output to file, or '-' for STDERR (default: #{options[:log]})") do |logfile|
    options[:log] = logfile
  end

  options[:loglevel] = 'info'
  opts.on('--debug', "Turn on debug output") do
    options[:loglevel] = 'debug'
  end
  opts.on('--quiet', "Turn off info output") do
    options[:loglevel] = 'warn'
  end

  options[:daemonize] = false
  opts.on('--daemonize', "Run in background") do
    options[:daemonize] = true
  end

  opts.on_tail('-h', '--help', "Display this help.") do
    puts opts
    exit
  end
end.parse!

Thread.abort_on_exception = true

disservice = Disservice::Disservice.new(options)
disservice.run_server
