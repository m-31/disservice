#!/usr/bin/env ruby

require 'optparse'
require 'socket'
require 'digest/sha1'

module Disservice
  VERSION = '0.2'

  class Disservice
    def initialize(options)
      if options[:daemonize]
        logfile = [$0.sub(/\.rb$/, ''), options[:port], options[:dsthost], options[:dstport]].join('_') << '.log'
        Process.daemon(true, true)
        $stderr.puts "running in the background (pid: #{$$}), logfile: #{logfile}"
        File.open($0 << '.pid', 'w'){ |f| f.write($$) }
        STDIN.reopen "/dev/null"
        STDOUT.reopen logfile, "a"
        STDERR.reopen logfile, "a"
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
    def initialize(mocks_dir)
      mocks_dir << '/' unless mocks_dir =~ /\/$/

      @mocks_dir = mocks_dir

      @request_map = {}
      @not_persisted = []

      Logger.info "reading mocks from #{mocks_dir}"
      Dir.glob(@mocks_dir << '**/*') do |fn|
        s = File.open(fn){ |f| f.read }
        request, response = s.split(/\r?\n\r?\n/, 2)
        request_line, header = request.split(/\r?\n/, 2)
        add(request, response, {fn: fn})
        Logger.debug '  ' << fn << ' => ' << request_line
      end
    end

    def try_match(request_line)
      self.fetch(self.find(request_line))
    end

    def find(request_line)
      @request_map.keys.find do |k|
        File.fnmatch(k, request_line)
      end
    end

    def fetch(key)
      @request_map[key]
    end

    def store(request, response)
      request_line, header = request.split(/\r?\n/, 2)
      if find(request_line)
        Logger.debug "not storing already known request: \"#{request_line}\""
      else
        Logger.debug "storing new request: \"#{request_line}\""
        add(request, response)
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
          host = host.strip.split(/: /, 2).last.gsub(/:/, '_')
          h = Digest::SHA1.hexdigest(header)[0..7]

          fn = [host, request_line.gsub(/[\s:+*#]/, '_').gsub(/[\/\\?]/, '-'), h].join('_')
          Logger.debug "persisting \"#{request_line}\" to #{@mocks_dir << fn}"
          value = @request_map[request_line]
          File.open(@mocks_dir << fn, 'w') do |f|
            f.write(request)
            f.write(value[:response])
          end
        end
        @not_persisted = []
      end
    end

    private
    def add(request, response, options={})
      request_line = request.lines.first.strip
      @request_map[request_line] = options.merge({request: request, response: response})
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
    end

    def run
      begin
        @socket = TCPServer.new(@port)
        @socket.listen(@backlog)
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
        Logger.info 'Exiting.'
      end
    end

    def accept_request(connection_count, to_client)
      begin
        _, peerport, peeraddr = to_client.peeraddr

        request = ''
        response = ''

        request_line = to_client.readline
        request << request_line

        verb = request_line[/^\w+/]
        url = request_line[/^\w+\s+(\S+)/, 1]
        version = request_line[/HTTP\/(1\.\d)\s*$/, 1]
        #uri = URI::parse(url)

        matched_request = @mocker.find(request_line.strip) if @options[:known] == 'replay'
        Logger.info "##{connection_count}: #{peeraddr}:#{peerport} #{verb} #{url} HTTP/#{version} \"#{matched_request || '-'}\""

        if matched_request && @options[:known] == 'replay'
          response = @mocker.fetch(matched_request)
          to_client.write(response[:response])
          to_client.close
        else
          # unknown request
          raise Exception if @options[:unknown] == 'croak' && !matched_request
          to_server = TCPSocket.new(@dsthost, @dstport || 80)
          to_server.write(request_line)

          content_len = 0

          loop do
            line = to_client.readline
            request << line

            if line =~ /^Content-Length:\s+(\d+)\s*$/
              content_len = $1.to_i
            end

            if line.strip.empty?
              to_server.write("Connection: close\r\n\r\n")

              if content_len >= 0
                to_server.write(to_client.read(content_len))
              end

              break
            else
              to_server.write(line)
            end
          end

          buff = ""
          loop do
            to_server.read(4096, buff)
            to_client.write(buff)
            response << buff
            break if buff.size < 4096
          end

          to_client.close
          to_server.close

          @mocker.store(request, response) if @options[:unknown] == 'record' && !matched_request
        end
      rescue Exception => e
        Logger.error "##{connection_count}: Socket error: #{e}"
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
