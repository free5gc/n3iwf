package udp_server

import (
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"gofree5gc/src/n3iwf/factory"
	"gofree5gc/src/n3iwf/logger"
	"gofree5gc/src/n3iwf/n3iwf_handler/n3iwf_message"
)

// IKE daemon listen on UDP 500 and 4500
// IP address can be suppport to set according to configuration file
// TODO: IPaddr configure
const (
	maxQueueSize       int = 100000
	defaultIKEPort500  int = 20500
	defaultIKEPort4500 int = 24500
)

type sendParameters struct {
	DstAddr *net.UDPAddr
	Length  int
	Payload []byte
}

var ikeLog *logrus.Entry

var sendChanToPort500 chan sendParameters // Chennel ID 1
var mtx1 sync.Mutex

var sendChanToPort4500 chan sendParameters // Chennel ID 2
var mtx2 sync.Mutex

func init() {
	// init logger
	ikeLog = logger.IKELog
	// init channel
	sendChanToPort500 = make(chan sendParameters, maxQueueSize)
	sendChanToPort4500 = make(chan sendParameters, maxQueueSize)
}

func Run() {

	listenAddrPort500 := new(net.UDPAddr)
	listenAddrPort4500 := new(net.UDPAddr)

	configBindAddr(listenAddrPort500, listenAddrPort4500)

	listener1, err := net.ListenUDP("udp", listenAddrPort500)
	if err != nil {
		ikeLog.Errorf("[IKE] Listen on UDP socket failed: %+v", err)
		return
	}

	go reader(1, listener1)
	go sender(1, listener1)

	listener2, err := net.ListenUDP("udp", listenAddrPort4500)
	if err != nil {
		ikeLog.Errorf("[IKE] Listen on UDP socket failed: %+v", err)
		return
	}

	go reader(2, listener2)
	go sender(2, listener2)

}

func configBindAddr(listenAddrPort500 *net.UDPAddr, listenAddrPort4500 *net.UDPAddr) {
	// Configure UDP port
	listenAddrPort500.Port, listenAddrPort4500.Port = defaultIKEPort500, defaultIKEPort4500

	// Configure IP address
	config := factory.N3iwfConfig.Configuration
	if config != nil {
		if config.IKEBindAddr != "" {
			ip := net.ParseIP(config.IKEBindAddr)
			if ip != nil {
				ikeLog.Tracef("[IKE] Binding %v", ip)
				listenAddrPort500.IP, listenAddrPort4500.IP = ip, ip
			} else {
				ikeLog.Warn("[IKE] Invalid IKE bind IP address, binding 0.0.0.0")
				listenAddrPort500.IP, listenAddrPort4500.IP = net.IPv4zero, net.IPv4zero
			}
		} else {
			ikeLog.Warn("[IKE] No IP address configuration available, binding 0.0.0.0")
			listenAddrPort500.IP, listenAddrPort4500.IP = net.IPv4zero, net.IPv4zero
		}
	} else {
		ikeLog.Warn("[IKE] No IP address configuration available, binding 0.0.0.0")
		listenAddrPort500.IP, listenAddrPort4500.IP = net.IPv4zero, net.IPv4zero
	}
}

func Send(sendInfo *n3iwf_message.UDPSendInfoGroup, msg []byte) {
	if sendInfo.ChannelID == 1 {

		sendData := sendParameters{
			DstAddr: sendInfo.Addr,
			Length:  len(msg),
			Payload: msg,
		}

		mtx1.Lock()
		sendChanToPort500 <- sendData
		mtx1.Unlock()

	} else if sendInfo.ChannelID == 2 {

		sendData := sendParameters{
			DstAddr: sendInfo.Addr,
			Length:  len(msg),
			Payload: msg,
		}

		mtx2.Lock()
		sendChanToPort4500 <- sendData
		mtx2.Unlock()

	} else {
		ikeLog.Error("[IKE] Send(): Invalid channel ID")
	}
}

func sender(channelID int, c *net.UDPConn) {
	if channelID == 1 {
		for {

			sendData := <-sendChanToPort500

			n, err := c.WriteToUDP(sendData.Payload, sendData.DstAddr)
			if err != nil {
				ikeLog.Errorf("[IKE] Sending data through UDP failed: %+v", err)
			}
			if n != sendData.Length {
				ikeLog.Warn("[IKE] There is data not being sent")
			}

		}
	} else if channelID == 2 {
		for {

			sendData := <-sendChanToPort4500

			n, err := c.WriteToUDP(sendData.Payload, sendData.DstAddr)
			if err != nil {
				ikeLog.Errorf("[IKE] Sending data through UDP failed: %+v", err)
			}
			if n != sendData.Length {
				ikeLog.Warn("[IKE] There is data not being sent")
			}

		}
	} else {
		ikeLog.Error("[IKE] sender(): Invalid channel ID")
	}
}

func reader(channelID int, conn *net.UDPConn) {

	if channelID > 2 {
		ikeLog.Error("[IKE] Channel ID out of range")
		return
	}

	data := make([]byte, 65535)

	for {

		n, remoteAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			ikeLog.Errorf("[IKE] Read from UDP failed: %+v", err)
			continue
		}

		sendInfo := &n3iwf_message.UDPSendInfoGroup{
			ChannelID: channelID,
			Addr:      remoteAddr,
		}

		msg := n3iwf_message.HandlerMessage{
			Event:       n3iwf_message.EventN1UDPMessage,
			UDPSendInfo: sendInfo,
			Value:       data[:n],
		}

		n3iwf_message.SendMessage(msg)

	}

}
