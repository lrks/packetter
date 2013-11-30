# encoding: utf-8
#******************************************************************************#
#*                                                                            *#
#*                                 Packetter                                  *#
#*                                                                            *#
#******************************************************************************#
require_relative 'pio-l4hdr'
require 'pp'
require 'socket'
require 'tweetstream'
#require 'uri'
require 'cgi'

#*------------------------------------*#
#*            パケット送る            *#
#*------------------------------------*#
class Packet
	ETH_P_ALL    = 0x03_00
	SIOCGIFINDEX = 0x89_33

	# 活きの良い生パケットを送る
	def sendRawPacket(data)
		sock = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, ETH_P_ALL)
		
		# struct ifreq in net/if.h
		ifreq = [@interface.dup].pack 'a32'
		sock.ioctl(SIOCGIFINDEX, ifreq)
		
		# struct sockaddr_ll in linux/if_packet.h
		sll = [Socket::AF_PACKET].pack 's'
		sll << ( [ETH_P_ALL].pack 's' )
		sll << ifreq[16..20]
		sll << ("\x00" * 12)
		sock.bind sll
		
		sock.send(data, 0)
		sock.close
	end

	# パケット職人
	def createPacket(payload)
		# TCP
		tdgm = Pio::TcpDatagram.new(
			:src_ip => @src_ip,
			:dst_ip => @dst_ip,
			:src_port => @src_port,
			:dst_port => @dst_port,
			:seq_number => @seq_number,
			:ack_number => @ack_number,
			:control_flag => @ctrl_flg,
			:window => @window,
			:urg_pointer => @urg_pointer,
			:optional_tlv => @option,
			:payload => payload,
		)
		
		# IP
		ippct = Pio::IPv4Packet.new(
			:payload => tdgm
		)
		
		# Ethernet
		ipfrm = Pio::IPv4Frame.new(
		  :src_mac => @src_mac,
		  :dst_mac => @dst_mac,
		  :packet => ippct
		)

		return ipfrm.to_binary
	end

	# ログ情報
	def printLog
		puts "[Interface]"
		puts "    #{@interface}"
		puts "[Address / Port]"
		puts "    eth.src == #{@src_mac} && eth.dst == #{@dst_mac}"
		puts "    ip.src == #{@src_ip} && ip.dst == #{@dst_ip}"
		puts "    tcp.srcport == #{@src_port} && tcp.dstport == #{@dst_port}"
	end

	# 細々したもの
	def sendPacket(payload)
		sendRawPacket(createPacket(payload))
		@seq_number += payload.bytesize
		#@ack_number += payload.bytesize
		#puts payload.bytesize
	end

	def setInterface(cq_pub) @interface = cq_pub end
	def setMacAddress(dst, src) @dst_mac, @src_mac = dst, src end
	def setIpAddress(dst, src) @dst_ip, @src_ip = dst, src end
	def setPortNumber(dst, src) @dst_port, @src_port = dst, src end
	def setSeqAckNumber(seq, ack) @seq_number, @ack_number = seq, ack end
	def setControlFlag(flg) @ctrl_flg = flg end
	def setWindowSize(size) @window = size end
	def setURG(flg) @urg_pointer = flg end
	def setPioOption(option) @option = option end
end


#*------------------------------------*#
#*      ASCII素通しURIエンコード      *#
#*------------------------------------*#
def uriEncode(str)
	ret = ""
	str.each_char do |c|
		ret << ((c.ord.between?(32, 126)) ? c : CGI.escape(c))
	end
	return ret
end


#*----------------------------------------------------------------------------*#
#*                                ここから本番                                *#
#*----------------------------------------------------------------------------*#
#
# パケット下準備
#
pkt = Packet.new()
pkt.setInterface("lo")	# 茜新社かな?
pkt.setMacAddress("54:52:00:01:00:02", "04:20:9a:44:cf:63")
pkt.setIpAddress("192.168.39.39", "192.168.114.51")
pkt.setPortNumber(80, 25252)
pkt.setSeqAckNumber(0x0, 0x0)
pkt.setControlFlag(Pio::TcpHeader::CF_ACK)
pkt.setWindowSize(65535)
pkt.setURG(0x0)
pkt.setPioOption([
	{ :mss => { :segment_size => 1460 } },
	:noop,
	{ :wsopt => { :shift_count => 8 } },
	:noop,
	:noop,
	:sackp
])

#
# Twitter下準備
#
TweetStream.configure do |config|
	config.consumer_key = 'CONSUMER_KEY'
	config.consumer_secret = 'CONSUMER_SECRET'
	config.oauth_token = 'OAUTH_TOKEN'
	config.oauth_token_secret = 'OAUTH_TOKEN_SECRET'
	config.auth_method = :oauth 
end

#
# TL取ってWiresharkに出るようにする
#
# とりあえず表示
pkt.printLog()

# TL取ってくる
client = TweetStream::Client.new
client.userstream do |status|
	# 下ごしらえ
	name = status.user.screen_name
	text = uriEncode(status.text)

	# 表示
	pkt.sendPacket("GET /#{name} => #{text} HTTP/1.1\r\n\r\n");
end

