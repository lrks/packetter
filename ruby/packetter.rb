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
# 設定
#
load '../config/twitter.conf'
load '../config/packet.conf'

twitter_config = $api
packet_config = $packet


#
# パケット下準備
#
pkt = Packet.new()
pkt.setInterface(packet_config[:interface])
pkt.setMacAddress(packet_config[:eth][:dst], packet_config[:eth][:src])
pkt.setIpAddress(packet_config[:nw][:dst], packet_config[:nw][:src])
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
	config.consumer_key = twitter_config[:consumer_key]
	config.consumer_secret = twitter_config[:consumer_secret]
	config.oauth_token = twitter_config[:token]
	config.oauth_token_secret = twitter_config[:token_secret]
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
	Thread.new do
		name = status.user.screen_name
		text = packet_config[:unicode] ? status.text : uriEncode(status.text)
		method = 
			(!twitter_config[:user].nil? && twitter_config[:user] == name) ? 
			'POST' : 
			'GET'

		# 表示
		pkt.sendPacket("#{method} /#{name} => #{text} HTTP/1.1\r\n\r\n");
	end
end

