package ike_message

func BuildIKEHeader(
	initiatorSPI uint64,
	responsorSPI uint64,
	exchangeType uint8,
	flags uint8,
	messageID uint32) *IKEMessage {

	ikeMessage := new(IKEMessage)

	ikeMessage.InitiatorSPI = initiatorSPI
	ikeMessage.ResponderSPI = responsorSPI
	ikeMessage.Version = 0x20
	ikeMessage.ExchangeType = exchangeType
	ikeMessage.Flags = flags
	ikeMessage.MessageID = messageID

	return ikeMessage
}

func BuildNotification(protocolID uint8, notifyMessageType uint16, spi []byte, notificationData []byte) *Notification {
	notificationPayload := new(Notification)
	notificationPayload.ProtocolID = protocolID
	notificationPayload.NotifyMessageType = notifyMessageType
	notificationPayload.SPI = append(notificationPayload.SPI, spi...)
	notificationPayload.NotificationData = append(notificationPayload.NotificationData, notificationData...)
	return notificationPayload
}

func BuildCertificate(certificateEncode uint8, certificateData []byte) *Certificate {
	certificatePayload := new(Certificate)
	certificatePayload.CertificateEncoding = certificateEncode
	certificatePayload.CertificateData = append(certificatePayload.CertificateData, certificateData...)
	return certificatePayload
}

func BuildEncryptedPayload(nextPayload IKEType, encryptedData []byte) *Encrypted {
	encryptedPayload := new(Encrypted)
	encryptedPayload.NextPayload = uint8(nextPayload)
	encryptedPayload.EncryptedData = append(encryptedPayload.EncryptedData, encryptedData...)
	return encryptedPayload
}

func BuildIdentificationInitiator(idType uint8, idData []byte) *IdentificationInitiator {
	identification := new(IdentificationInitiator)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	return identification
}

func BuildIdentificationResponder(idType uint8, idData []byte) *IdentificationResponder {
	identification := new(IdentificationResponder)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	return identification
}

func BuildAuthentication(authenticationMethod uint8, authenticationData []byte) *Authentication {
	authentication := new(Authentication)
	authentication.AuthenticationMethod = authenticationMethod
	authentication.AuthenticationData = append(authentication.AuthenticationData, authenticationData...)
	return authentication
}

func BuildConfigurationPayload(configurationType uint8, attributes []*IndividualConfigurationAttribute) *Configuration {
	configuration := new(Configuration)
	configuration.ConfigurationType = configurationType
	configuration.ConfigurationAttribute = append(configuration.ConfigurationAttribute, attributes...)
	return configuration
}

func BuildConfigurationAttribute(attributeType uint16, attributeValue []byte) *IndividualConfigurationAttribute {
	configurationAttribute := new(IndividualConfigurationAttribute)
	configurationAttribute.Type = attributeType
	configurationAttribute.Value = append(configurationAttribute.Value, attributeValue...)
	return configurationAttribute
}

func BuildTrafficSelectorInitiator(trafficSelectors []*IndividualTrafficSelector) *TrafficSelectorInitiator {
	trafficSelectorInitiator := new(TrafficSelectorInitiator)
	trafficSelectorInitiator.TrafficSelectors = append(trafficSelectorInitiator.TrafficSelectors, trafficSelectors...)
	return trafficSelectorInitiator
}

func BuildTrafficSelectorResponder(trafficSelectors []*IndividualTrafficSelector) *TrafficSelectorResponder {
	trafficSelectorResponder := new(TrafficSelectorResponder)
	trafficSelectorResponder.TrafficSelectors = append(trafficSelectorResponder.TrafficSelectors, trafficSelectors...)
	return trafficSelectorResponder
}

func BuildIndividualTrafficSelector(tsType uint8, ipProtocolID uint8, startPort uint16, endPort uint16, startAddr []byte, endAddr []byte) *IndividualTrafficSelector {
	trafficSelector := new(IndividualTrafficSelector)
	trafficSelector.TSType = tsType
	trafficSelector.IPProtocolID = ipProtocolID
	trafficSelector.StartPort = startPort
	trafficSelector.EndPort = endPort
	trafficSelector.StartAddress = append(trafficSelector.StartAddress, startAddr...)
	trafficSelector.EndAddress = append(trafficSelector.EndAddress, endAddr...)
	return trafficSelector
}

func BuildEAPfailure(identifier uint8) *EAP {
	eap := new(EAP)
	eap.Code = EAPCodeFailure
	eap.Identifier = identifier
	return eap
}
