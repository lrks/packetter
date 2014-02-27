# -*- coding: utf-8 -*-

#
# stereocat / packetgen_tcp.rb
# https://gist.github.com/stereocat/6839659
#

require "forwardable"
require 'rubygems'
require 'bindata'
require 'pio'

module Pio

  module HeaderUtil
    def get_checksum csum, val
      # $stderr.puts("val : #{sprintf("%06x, %04x", csum, val)}")

      sum = ( ~csum & 0xffff ) + val
      while sum > 0xffff
        sum = ( sum & 0xffff ) + ( sum >> 16 )
      end
      ~sum & 0xffff
    end

    def get_str_checksum csum, str
      dbyte = 0
      str.each_byte do | byte |
        if dbyte == 0
          dbyte = byte << 8
        else
          dbyte = dbyte + byte
          csum = get_checksum( csum, dbyte )
          dbyte = 0
        end
      end
      # padding (align 16bit)
      csum = get_checksum( csum, dbyte ) if dbyte != 0
      return csum
    end
  end

  ############################################################
  ## IPv4
  ############################################################

  class IPv4FrameHeader < BinData::Record
    extend Type::EthernetHeader
    endian :big
    ethernet_header :ether_type => 0x0800
  end

  class IPv4Frame
    extend Forwardable

    attr_reader :src_mac
    attr_reader :dst_mac
    attr_reader :frame_hdr
    attr_reader :packet

    def_delegators :@frame_hdr, :ether_type

    # minimum frame length = 60 octets
    MIN_FRAME_LEN = 60
    # ethernet header length = 14 octets
    #   [ mac:6octets * 2 + ether-type 2octets ]
    ETH_HEADER_LEN = 14
    # minimum packet length (octets)
    # packet must be larger than 46 octets = 60 - 14
    MIN_PACKET_LEN = MIN_FRAME_LEN - ETH_HEADER_LEN

    def initialize opts
      if opts[ :frame_header ]
        @frame_hdr = opts[ :frame_header ] # IPv4FrameHeader
        @packet = opts[ :packet ] # IPv4Packet
        @src_mac = Mac.new( @frame_hdr.source_mac.to_s )
        @dst_mac = Mac.new( @frame_hdr.destination_mac.to_s )
      else
        @src_mac = Mac.new( opts[ :src_mac ] )
        @dst_mac = Mac.new( opts[ :dst_mac ] )
        @packet = opts[ :packet ] # IPv4Packet
        @frame_hdr = IPv4FrameHeader.new(
          :source_mac => @src_mac.to_a,
          :destination_mac => @dst_mac.to_a
        )
      end
    end

    def to_binary
      padcount = 0
      if @packet.total_length < MIN_PACKET_LEN
        padcount = MIN_PACKET_LEN - @packet.total_length
      end
      @frame_hdr.to_binary_s + @packet.to_binary + ( "\000" * padcount )
    end

    def self.read io
      io = StringIO.new(io, 'r') if String === io
      # 分割して read するので IO class compatible にする。
      frame = IPv4FrameHeader.read io
      ippct = IPv4Packet.read io
      IPv4Frame.new(
        :frame_header => frame,
        :packet => ippct
      )
    end
  end

  class IPv4Header < BinData::Record
    endian :big

    bit4   :version,         :value => 4
    bit4   :header_length,   :initial_value => 5 # without options
    uint8  :tos,             :initial_value => 0
    uint16 :total_length,    :value => lambda {
      payload.bytesize + header_length_in_bytes
    }
    uint16 :identification
    bit3   :flags,           :initial_value => 2 # 2:don't fragment
    bit13  :fragment_offset, :initial_value => 0
    uint8  :ttl,             :initial_value => 64
    uint8  :protocol
    uint16 :header_checksum, :initial_value => 0
    ip_address :src_ip
    ip_address :dst_ip
    string :options, :read_length => lambda {
      # length of ipv4 header without options is 20 octets
      header_length_in_bytes - 20
    }
    string :payload, :read_length => lambda {
      total_length - header_length_in_bytes
    }

    def header_length_in_bytes
      # IHL(internet header length) is 4 octets count
      header_length * 4
    end
  end

  class IPv4Packet
    extend Forwardable
    include HeaderUtil

    attr_reader :packet
    attr_reader :src_ip
    attr_reader :dst_ip

    def_delegator :@packet, :to_binary_s, :to_binary
    def_delegators :@packet, :version
    def_delegators :@packet, :header_length
    def_delegators :@packet, :tos
    def_delegators :@packet, :total_length
    def_delegators :@packet, :identification
    def_delegators :@packet, :flags
    def_delegators :@packet, :fragment_offset
    def_delegators :@packet, :ttl
    def_delegators :@packet, :protocol
    def_delegators :@packet, :header_checksum
    def_delegators :@packet, :src_ip
    def_delegators :@packet, :dst_ip
    def_delegators :@packet, :options
    def_delegators :@packet, :payload

    @@id = nil

    def id
      unless @@id
        srand Random.new_seed
        @@id = Random.rand(1..65535)
      else
        @@id = (@@id + 1) & 0xffff
      end
    end

    def initialize opts
      if opts[ :packet ]
        @packet   = opts[ :packet ]
        @src_ip   = @packet.src_ip
        @dst_ip   = @packet.dst_ip
        @protocol = @packet.protocol
        @payload  = @packet.payload
      else
        if opts[ :payload ]
          @payload = opts[ :payload ]
          case @payload
          when TransportLayerProtocol
            @src_ip   = @payload.src_ip
            @dst_ip   = @payload.dst_ip
            @protocol = @payload.protocol
          else
            raise ArgmentError, "## TBD ##"
          end
          @packet = IPv4Header.new(
            :src_ip => @src_ip.to_a,
            :dst_ip => @dst_ip.to_a,
            :protocol => @protocol,
            :identification => id,
            :payload => @payload.to_binary
          )
          @packet.header_checksum = header_checksum
        else
          raise ArgmentError
        end
      end
    end

    def self.read io
      iphdr = IPv4Header.read io
      IPv4Packet.new( :packet => iphdr )
    end

    def datagram
      case @protocol
      when 6  # tcp
        thdr = TcpHeader.read( @payload )
        TcpDatagram.new(
          :src_ip => @src_ip.to_s,
          :dst_ip => @dst_ip.to_s,
          :datagram => thdr
        )
      when 17 # udp
        uhdr = UdpHeader.read( @payload )
        UdpDatagram.new(
          :src_ip => @src_ip.to_s,
          :dst_ip => @dst_ip.to_s,
          :datagram => uhdr
        )
      end
    end

    def valid?
      csum = header_checksum
      csum = get_checksum( csum, @packet.header_checksum )
      return csum == 0 ? true : false
    end

    def header_checksum
      csum = 0
      csum = get_checksum( csum,
        @packet.version << 12 | @packet.header_length << 8  | @packet.tos )
      csum = get_checksum( csum, @packet.total_length )
      csum = get_checksum( csum, @packet.identification )
      csum = get_checksum( csum,
        @packet.flags << 13 + @packet.fragment_offset )
      csum = get_checksum( csum,
        @packet.ttl << 8 | @packet.protocol )
      csum = get_checksum( csum, @src_ip.to_i >> 16 )
      csum = get_checksum( csum, @src_ip.to_i & 0xffff )
      csum = get_checksum( csum, @dst_ip.to_i >> 16 )
      csum = get_checksum( csum, @dst_ip.to_i & 0xffff )
      # cannot handle ip options
      return csum
    end

  end

  ############################################################
  ## L4 Protocol Base
  ############################################################

  class TransportLayerProtocol
    extend Forwardable
    include HeaderUtil

    attr_reader :datagram # Bindata::Record Struct
    attr_reader :src_ip
    attr_reader :dst_ip
    # attr_reader :src_port
    # attr_reader :dst_port
    attr_reader :total_length
    # attr_reader :payload

    def_delegator :@datagram, :to_binary_s, :to_binary
    def_delegators :@datagram, :src_port
    def_delegators :@datagram, :dst_port
    def_delegators :@datagram, :checksum
    def_delegators :@datagram, :payload

    # abstract
    def protocol; 0; end

    # abstract
    def header_checksum; 0; end

    def valid?
      csum = header_checksum
      csum = get_checksum( csum, @datagram.checksum )
      return csum == 0 ? true : false
    end
  end

  ############################################################
  ## TCP
  ############################################################

  class TcpOption < BinData::Record
    endian :big
  end

  # class EndOfOptionList < TcpOption
  #   # tlv_type only
  # end

  # class NoOperation < TcpOption
  #   # tlv_type only
  # end

  class MaximumSegmentSize < TcpOption
    # type: 2
    bit8 :tlv_length, :value => 4
    bit16 :segment_size
  end

  class WindowScaleOption < TcpOption
    # type: 3
    bit8 :tlv_length, :value => 3
    bit8 :shift_count
  end

  class SackPermitted < TcpOption
    # type: 4
    bit8 :tlv_length, :value => 2
    # tlv_type and length only
  end

  class Sack < TcpOption
    # type: 5
    bit8 :tlv_length, :value => lambda {
      sequence_number_list.length * 4 + 2
    }
    array :sequence_number_list,
          :type => :bit32,
          :initial_length => lambda { ( tlv_length - 2 ) / 4 }
  end

  class TimeStampOption < TcpOption
    # type: 8
    bit8 :tlv_length, :value => 10
    bit32 :ts_val # timestamp vlaue
    bit32 :ts_ecr # timestamp reply
  end

  class PartialOrderConnectionPermitted < TcpOption
    # time: 9
    bit8 :tlv_length, :value => 2
  end

  class PartialOrderServiceProfile < TcpOption
    # type: 10
    bit8 :tlv_length, :value => 3
    bit1 :start_flag
    bit1 :end_flag
    bit6 :filler
  end

  class Cc < TcpOption
    # type: 11
    bit8 :tlv_length, :value => 6
    bit32 :connection_count
  end

  class CcNew < TcpOption
    # type: 12
    bit8 :tlv_length, :value => 6
    bit32 :connection_count
  end

  class CcEcho < TcpOption
    # type: 13
    bit8 :tlv_length, :value => 6
    bit32 :connection_count
  end

  class TcpAlternateChecksumRequest < TcpOption
    # type: 14
    bit8 :tlv_length, :value => 3
    bit8 :checksum
  end

  class TcpAlternateChecksumData < TcpOption
    # type: 15
    bit8 :tlv_length, :value => lambda {
      data.bytesize + 2
    }
    string :data
  end

  class TcpOptionalTlv < BinData::Record
    endian :big

    bit8   :tlv_type
    choice :tlv_body,
           :onlyif => lambda { not type_only? },
           :selection => :chooser do
      # end_of_option_list   0
      # no_operation         1
      maximum_segment_size 2
      window_scale_option  3
      sack_permitted       4
      sack                 5
      time_stamp_option    8
      partial_order_connection_permitted  9
      partial_order_service_profile      10
      cc                  11
      cc_new              12
      cc_echo             13
      tcp_alternate_checksum_request     14
      tcp_alternate_checksum_data        15
      string       "unknown"
    end

    def chooser
      case tlv_type
      when 2,3,4,5,8,9,10,11,12,13,14,15
        # $stderr.puts "## type = #{tlv_type}"
        tlv_type
      else
        "unknown"
      end
    end

    def end_of_option_list?
      tlv_type == 0
    end

    def type_only?
      tlv_type == 0 or tlv_type == 1
    end

    def bytesize
      case tlv_type
      when 0, 1
        1
      when 2,3,4,5,8,9,10,11,12,13,14,15
        tlv_body.tlv_length
      else
        0
      end
    end
  end

  class TcpHeader < BinData::Record
    endian :big

    CF_FIN = 0b000001
    CF_SYN = 0b000010
    CF_RST = 0b000100
    CF_PSH = 0b001000
    CF_ACK = 0b010000
    CF_URG = 0b100000

    uint16 :src_port
    uint16 :dst_port
    uint32 :seq_number
    uint32 :ack_number, :initial_value => 0
    bit4   :data_offset, :initial_value => lambda {
      # $stderr.puts "# A optlen: #{ option_length_in_bytes }"
      5 + option_length_in_bytes / 4
    }
    bit6   :reserved, :value => 0
    bit6   :control_flag, :initial_value => CF_SYN
    uint16 :window
    uint16 :checksum
    uint16 :urg_pointer, :initial_value => 0
    array  :optional_tlv,
           :type => :tcp_optional_tlv,
           :onlyif => :has_options?,
           :read_until => lambda {
      @readbytes ||= header_length_in_bytes - 20
      @readbytes = @readbytes - element.bytesize
      # $stderr.puts "# B optlen: #{ element.tlv_type} => #{ option_length_in_bytes }, #{ @readbytes }"
      element.end_of_option_list? or @readbytes <= 0
    }
    skip   :length => lambda { @readbytes or 0 }
    rest   :payload

    def has_options?
      data_offset > 5
    end

    def option_length_in_bytes
      bytes = 0
      if optional_tlv
        optional_tlv.each do | each |
          bytes += each.bytesize
        end
      end
      return bytes
    end

    def header_length_in_bytes
      # data_offset = tcp header length, 4 octets count
      data_offset * 4
    end

    def fin? ; ( control_flag & CF_FIN ) > 0 ; end
    def syn? ; ( control_flag & CF_SYN ) > 0 ; end
    def rst? ; ( control_flag & CF_RST ) > 0 ; end
    def psh? ; ( control_flag & CF_PSH ) > 0 ; end
    def ack? ; ( control_flag & CF_ACK ) > 0 ; end
    def urg? ; ( control_flag & CF_URG ) > 0 ; end
    def fin_ack? ; ( fin? and ack? ) ; end
    def syn_ack? ; ( syn? and ack? ) ; end
    def psh_ack? ; ( psh? and ack? ) ; end
  end

  class TcpDatagram < TransportLayerProtocol
    def_delegators :@datagram, :seq_number
    def_delegators :@datagram, :ack_number
    def_delegators :@datagram, :data_offset
    def_delegators :@datagram, :control_flag
    def_delegators :@datagram, :window
    def_delegators :@datagram, :urg_pointer
    def_delegators :@datagram, :optional_tlv
    def_delegators :@datagram, :fin?, :syn?, :rst?, :psh?, :ack?, :urg?
    def_delegators :@datagram, :fin_ack?, :syn_ack?, :psh_ack?

    def protocol; 6; end

    def initialize opts
      @src_ip = IPv4Address.new( opts[ :src_ip ] )
      @dst_ip = IPv4Address.new( opts[ :dst_ip ] )

      if opts[ :datagram ]
        @datagram      = opts[ :datagram ]
        @src_port      = @datagram.src_port
        @dst_port      = @datagram.dst_port
        @payload       = @datagram.payload
        @seq_number    = @datagram.seq_number
        @ack_number    = @datagram.ack_number
        @control_flag  = @datagram.control_flag
        @window        = @datagram.window
        @urg_pointer   = @datagram.urg_pointer
        # array of TcpOptionalTlv
        @options       = @datagram.optional_tlv
        @total_length  = @datagram.to_binary_s.bytesize
        @header_length = @datagram.header_length_in_bytes

        # $stderr.puts "#[B] hdrlen=#{@header_length}, tlen=#{@total_length}"

        # TBD
        # ハンパなheaderわたされることを想定して
        # 各パラメタの再計算をするか?
      else
        @src_port      = opts[ :src_port ]
        @dst_port      = opts[ :dst_port ]
        @payload       = opts[ :payload ]
        @seq_number    = opts[ :seq_number ]
        @ack_number    = opts[ :ack_number ]
        @control_flag  = opts[ :control_flag ] || Pio::TcpHeader::CF_SYN
        @window        = opts[ :window ]
        @urg_pointer   = opts[ :urg_pointer ] || 0
        # array of TcpOptionalTlv
        @options       = options_by( opts[ :optional_tlv ] )

        # TBD
        # need total_length and header_length (data_offset)
        # to calculate checksum!
        # Optionsの処理を先にどうにかしたほうがいいか...

        # header = fixed fields (20 bytes) + option fields length
        @header_length = 20 + option_length_in_bytes
        @total_length  = @header_length + @payload.bytesize

        # $stderr.puts "#[A] hdrlen=#{@header_length}, tlen=#{@total_length}"

        @datagram = TcpHeader.new(
          :src_port     => @src_port,
          :dst_port     => @dst_port,
          :seq_number   => @seq_number,
          :ack_number   => @ack_number,
          :control_flag => @control_flag,
          :window       => @window,
          :urg_pointer  => @urg_pointer,
          :checksum     => header_checksum,
          :optional_tlv => @options,
          :payload      => @payload
        )
      end
    end

    def header_checksum
      csum = 0
      # pseudo header
      csum = get_checksum( csum, @src_ip.to_i >> 16 )
      csum = get_checksum( csum, @src_ip.to_i & 0xffff )
      csum = get_checksum( csum, @dst_ip.to_i >> 16 )
      csum = get_checksum( csum, @dst_ip.to_i & 0xffff )
      csum = get_checksum( csum, protocol & 0x00ff )
      csum = get_checksum( csum, @total_length )
      # tcp header (without checksum)
      csum = get_checksum( csum, @src_port )
      csum = get_checksum( csum, @dst_port )
      csum = get_checksum( csum, @seq_number >> 16 )
      csum = get_checksum( csum, @seq_number & 0xffff )
      csum = get_checksum( csum, @ack_number >> 16 )
      csum = get_checksum( csum, @ack_number & 0xffff )
      # $stderr.puts "hdrlen=#{@header_length}, flag=#{@control_flag}, value=#{sprintf("%04x", (( @header_length/4 << 12 ) & 0xf000 | @control_flag))}"
      csum = get_checksum( csum,
        ( @header_length/4 << 12 ) & 0xf000 | @control_flag
      )
      csum = get_checksum( csum, @window )
      csum = get_checksum( csum, @urg_pointer )
      # tcp options
      csum = get_str_checksum( csum, @options.map{ |e| e.to_binary_s }.join )
      # payload
      csum = get_str_checksum( csum, @payload.to_s )

      return csum
    end

    def options_by opt_words
      return [] unless opt_words
      # opt_words format:
      # [
      #   :tlv_type_symbol,
      #   { :tlv_type_symbol => {
      #       :arg_symbol => value,
      #       :arg_symbol => value,
      #       ...
      #     }},
      #   ...
      # ]

      opts = []
      opt_words.each do | each |
        case each
        when Symbol
          if type = option_type_table[ each ]
            opts.push Pio::TcpOptionalTlv.new(
              :tlv_type => type
            )
          else
            $stderr.puts "warning: unknown option: #{each}"
          end
        when Hash
          ( type_sym, arg ) = each.to_a.shift
          if type = option_type_table[ type_sym ]
            opts.push Pio::TcpOptionalTlv.new(
              :tlv_type => type,
              :tlv_body => arg
            )
          else
            $stderr.puts "warning: unknown option: #{type_sym}"
          end
        end
      end
      return opts
    end

    def option_type_table
      {
        # short
        :eol    =>  0,
        :noop   =>  1,
        :mss    =>  2,
        :wsopt  =>  3,
        :sackp  =>  4,
        :tsopt  =>  8,
        :pocp   =>  9,
        :posp   => 10,
        :tcpacr => 14,
        :tcpacd => 15,
        # long
        :end_of_option_list   =>  0,
        :no_operation         =>  1,
        :maximum_segment_size =>  2,
        :window_scale_option  =>  3,
        :sack_permitted       =>  4,
        :sack                 =>  5,
        :time_stamp_option    =>  8,
        :partial_order_connection_permitted =>  9,
        :partial_order_service_profile      => 10,
        :cc                   => 11,
        :cc_new               => 12,
        :cc_echo              => 13,
        :tcp_alternate_checksum_request     => 14,
        :tcp_alternate_checksum_data        => 15
      }
    end

    def option_length_in_bytes
      bytes = 0
      if @options
        @options.each do | each |
          bytes = bytes + each.bytesize
        end
      end
      return bytes
    end

  end

  class TcpServer
    attr_reader :curr_state

    def initialize
      @curr_state = :closed
      srand Random.new_seed
      @seq = Random.rand(1..0xffffffff)
      @handler = {}
    end

    def send_handler &block
      @handler[ :send ] = block
    end

    def request_handler &block
      @handler[ :request ] = block
    end

    def response_datagram req_dgm, ack, cflag, payload
      TcpDatagram.new(
        :src_ip => req_dgm.dst_ip.to_s,
        :dst_ip => req_dgm.src_ip.to_s,
        :src_port => req_dgm.dst_port,
        :dst_port => req_dgm.src_port,
        :seq_number => @seq,
        :ack_number => ack,
        :window => 2048, # ok?
        :control_flag => cflag,
        :optional_tlv => [],
        :payload => payload
      )
    end

    def calc_ack rcv_dgm, count
      @seq = rcv_dgm.ack_number unless rcv_dgm.ack_number == 0
      ( rcv_dgm.seq_number + count ) & 0xffffffff
    end

    def receive rcv_dgm
      case @curr_state
      when :closed, :listen
        if rcv_dgm.syn?
          ack = calc_ack( rcv_dgm, 1 )
          cflag = TcpHeader::CF_SYN | TcpHeader::CF_ACK
          reply_dgm = response_datagram( rcv_dgm, ack, cflag, '' )
          ## send syn_ack
          @handler[ :send ].call( reply_dgm )
          @curr_state = :syn_received
        end
      when :syn_received
        if rcv_dgm.ack?
          # finish handshake. wait request
          @curr_state = :established
        end
      when :established
        if rcv_dgm.fin?
          ack = calc_ack( rcv_dgm, 1 )
          cflag = TcpHeader::CF_ACK
          reply_dgm = response_datagram( rcv_dgm, ack, cflag, '' )
          ## send ack
          @handler[ :send ].call( reply_dgm )
          @curr_state = :close_wait
          cflag = TcpHeader::CF_FIN
          reply_dgm = response_datagram( rcv_dgm, ack, cflag, '' )
          ## send fin
          @handler[ :send ].call( reply_dgm )
          @curr_state = :last_ack
        elsif
          ## request processing
          ack = calc_ack( rcv_dgm, rcv_dgm.payload.bytesize )
          reply_dgm = @handler[ :request ].call( rcv_dgm, @seq, ack )
          ## send response
          @handler[ :send ].call( reply_dgm )
        end
      when :last_ack
        if rcv_dgm.ack?
          @curr_state = :closed
          puts "info, session closed."
        end
      else
        $stderr.puts "warning, receive out-of-state packet"
      end
    end

  end

  ############################################################
  ## UDP
  ############################################################

  class UdpHeader < BinData::Record
    endian :big

    UDP_HDR_LEN = 8

    uint16 :src_port
    uint16 :dst_port
    uint16 :total_length, :value => lambda {
      payload.bytesize + UDP_HDR_LEN
    }
    uint16 :checksum
    string :payload, :read_length => lambda {
      total_length - UDP_HDR_LEN
    }
  end

  class UdpDatagram < TransportLayerProtocol

    def protocol; 17; end

    def initialize opts
      @src_ip = IPv4Address.new( opts[ :src_ip ] )
      @dst_ip = IPv4Address.new( opts[ :dst_ip ] )

      if opts[ :datagram ]
        @datagram     = opts[ :datagram ]
        @src_port     = @datagram.src_port
        @dst_port     = @datagram.dst_port
        @total_length = @datagram.total_length
        @payload      = @datagram.payload
      else
        @src_port     = opts[ :src_port ]
        @dst_port     = opts[ :dst_port ]
        @payload      = opts[ :payload ]
        # udp datagram length
        # = payload length (octets) + udp header length (8 octets)
        @total_length = @payload.to_s.bytesize + 8

        @datagram = UdpHeader.new(
          :src_port     => @src_port,
          :dst_port     => @dst_port,
          :total_length => @total_length,
          :checksum     => header_checksum,
          :payload      => @payload
        )
      end
    end

    def header_checksum
      csum = 0
      # pseudo header
      csum = get_checksum( csum, @src_ip.to_i >> 16 )
      csum = get_checksum( csum, @src_ip.to_i & 0xffff )
      csum = get_checksum( csum, @dst_ip.to_i >> 16 )
      csum = get_checksum( csum, @dst_ip.to_i & 0xffff )
      csum = get_checksum( csum, protocol & 0x00ff )
      csum = get_checksum( csum, @total_length )
      # udp header (without checksum)
      csum = get_checksum( csum, @src_port )
      csum = get_checksum( csum, @dst_port )
      csum = get_checksum( csum, @total_length )
      # udp payload
      csum = get_str_checksum( csum, @payload.to_s )

      return csum
    end
  end

end
