require 'socket'
require 'optparse'
require 'timeout'

class Ping
  ICMP_ECHO_REPLY = 0 # Echo reply
  ICMP_ECHO      = 8 # Echo request
  ICMP_SUBCODE   = 0

  def initialize(host:)
    @host = host
  end

  # refs: https://www.rfc-editor.org/rfc/rfc792
  #
  #  0                   1                   2                   3
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |     Type      |     Code      |          Checksum             |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |           Identifier          |        Sequence Number        |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |     Data ...
  # +-+-+-+-+-
  def ping
    socket = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    sequence_number = 1 # NOTE: 一度しかリクエストを送らないので固定値を設定
    identifier = 1 # NOTE: 一度しかリクエストを送らないので固定値を設定
    data = nil
    sockaddr = Socket.pack_sockaddr_in(nil, @host)

    # C: unsigned char (8bit 符号なし整数)
    # n: ネットワークバイトオーダー(ビッグエンディアン)のunsigned short (16bit 符号なし整数)
    # A: ASCII文字列(スペースを詰める/後続するヌル文字やスペースを削除)
    pack_template = 'C2 n3 A' << @data_size.to_s

    # checksum計算時checksumフィールドは0
    checksum = 0
    message = [ICMP_ECHO, ICMP_SUBCODE, checksum, identifier, sequence_number, data].pack(pack_template)

    checksum = checksum(message)
    message = [ICMP_ECHO, ICMP_SUBCODE, checksum, identifier, sequence_number, data].pack(pack_template)

    timeout = 5
    bool = false

    begin
      saddr = Socket.pack_sockaddr_in(0, @host)
    rescue Exception
      socket.close unless socket.closed?
      return bool
    end

    start_time = Time.now

    socket.send(message, 0, saddr)

    begin
      Timeout.timeout(timeout){
        while true
          reply_identifier = nil
          reply_sequence_number = nil

          reply_message = socket.recvfrom(1500).first
          type = reply_message[20, 1].unpack('C1').first

          case type
          when ICMP_ECHOREPLY
            if reply_message.length >= 28
              reply_identifier, reply_sequence_number = reply_message[24, 4].unpack('n3')
            end
          else
            return 'Unexpect response'
          end

          if reply_identifier == identifier && reply_sequence_number == sequence_number && type == ICMP_ECHOREPLY
            bool = true
            break
          end
        end
      }
    rescue Timeout::Error
      return 'timeout'
    rescue Exception => e
      return'Unexpected error'
    ensure
      socket.close if socket
    end

    duration = Time.now - start_time if bool
  end

  private

  # refs: https://www.rfc-editor.org/rfc/rfc1071
  def checksum(message)
    message_length    = message.length
    check     = 0

    message.unpack('n*').each do |el|
      check += el
    end

    if message_length % 2 > 0
      check += message[-1].unpack('C1').first << 8
    end

    check = (check >> 16) + (check & 0xffff)
    return ~((check >> 16) +  (check & 0xffff))
  end
end

def parse_options
  options = {}
  option_parser = OptionParser.new
  option_parser.on('-h host') { |host| options[:host] = host }
  option_parser.parse!(ARGV)
  options
end

options = parse_options
puts Ping.new(host: options[:host]).ping
