package handler

import (
	"encoding/binary"
	"errors"

	"github.com/free5gc/aper"
	"github.com/free5gc/n3iwf/pkg/ike/message"
	"github.com/free5gc/ngap/ngapType"
)

// 3GPP specified EAP-5G

// Access Network Parameters
type ANParameters struct {
	GUAMI              *ngapType.GUAMI
	SelectedPLMNID     *ngapType.PLMNIdentity
	RequestedNSSAI     *ngapType.AllowedNSSAI
	EstablishmentCause *ngapType.RRCEstablishmentCause
}

func UnmarshalEAP5GData(codedData []byte) (eap5GMessageID uint8, anParameters *ANParameters, nasPDU []byte, err error) {
	if len(codedData) >= 2 {
		ikeLog.Debug("===== Unmarshal EAP5G Data (Ref: TS24.502 Fig. 9.3.2.2.2-1) =====")

		eap5GMessageID = codedData[0]
		ikeLog.Debugf("Message-Id: %d", eap5GMessageID)
		if eap5GMessageID == message.EAP5GType5GStop {
			return
		}

		codedData = codedData[2:]

		// [TS 24.502 f30] 9.3.2.2.2.3
		// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
		// Therefore, IEI of AN-parameter is not needed to be included.
		// anParameter = AN-parameter Type | AN-parameter Length | Value part of IE

		if len(codedData) >= 2 {
			// Length of the AN-Parameter field
			anParameterLength := binary.BigEndian.Uint16(codedData[:2])
			ikeLog.Debugf("AN-parameters length: %d", anParameterLength)

			if anParameterLength != 0 {
				anParameterField := codedData[2:]

				// Bound checking
				if len(anParameterField) < int(anParameterLength) {
					ikeLog.Error("Packet contained error length of value")
					return 0, nil, nil, errors.New("Error formatting")
				} else {
					anParameterField = anParameterField[:anParameterLength]
				}

				ikeLog.Debugf("Parsing AN-parameters...: % v", anParameterField)

				anParameters = new(ANParameters)

				// Parse AN-Parameters
				for len(anParameterField) >= 2 {
					parameterType := anParameterField[0]
					// The AN-parameter length field indicates the length of the AN-parameter value field.
					parameterLength := anParameterField[1]

					switch parameterType {
					case message.ANParametersTypeGUAMI:
						ikeLog.Debugf("-> Parameter type: GUAMI")
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("Error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != message.ANParametersLenGUAMI {
								return 0, nil, nil, errors.New("Unmatched GUAMI length")
							}

							guamiField := make([]byte, 1)
							guamiField = append(guamiField, parameterValue...)
							// Decode GUAMI using aper
							ngapGUAMI := new(ngapType.GUAMI)
							err := aper.UnmarshalWithParams(guamiField, ngapGUAMI, "valueExt")
							if err != nil {
								ikeLog.Errorf("APER unmarshal with parameter failed: %+v", err)
								return 0, nil, nil, errors.New("Unmarshal failed when decoding GUAMI")
							}
							anParameters.GUAMI = ngapGUAMI
							ikeLog.Debugf("Unmarshal GUAMI: % x", guamiField)
							ikeLog.Debugf("\tGUAMI: PLMNIdentity[% x], "+
								"AMFRegionID[% x], AMFSetID[% x], AMFPointer[% x]",
								anParameters.GUAMI.PLMNIdentity, anParameters.GUAMI.AMFRegionID,
								anParameters.GUAMI.AMFSetID, anParameters.GUAMI.AMFPointer)
						} else {
							ikeLog.Warn("AN-Parameter GUAMI field empty")
						}
					case message.ANParametersTypeSelectedPLMNID:
						ikeLog.Debugf("-> Parameter type: ANParametersTypeSelectedPLMNID")
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("Error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != message.ANParametersLenPLMNID {
								return 0, nil, nil, errors.New("Unmatched PLMN ID length")
							}

							plmnField := make([]byte, 1)
							plmnField = append(plmnField, parameterValue...)
							// Decode PLMN using aper
							ngapPLMN := new(ngapType.PLMNIdentity)
							err := aper.UnmarshalWithParams(plmnField, ngapPLMN, "valueExt")
							if err != nil {
								ikeLog.Errorf("APER unmarshal with parameter failed: %v", err)
								return 0, nil, nil, errors.New("Unmarshal failed when decoding PLMN")
							}
							anParameters.SelectedPLMNID = ngapPLMN
							ikeLog.Debugf("Unmarshal SelectedPLMNID: % x", plmnField)
							ikeLog.Debugf("\tSelectedPLMNID: % x", anParameters.SelectedPLMNID.Value)
						} else {
							ikeLog.Warn("AN-Parameter PLMN field empty")
						}
					case message.ANParametersTypeRequestedNSSAI:
						ikeLog.Debugf("-> Parameter type: ANParametersTypeRequestedNSSAI")
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("Error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							ngapNSSAI := new(ngapType.AllowedNSSAI)

							// [TS 24501 f30] 9.11.2.8 S-NSSAI
							// s-nssai(LV) consists of
							// len(1 byte) | SST(1) | SD(3,opt) | Mapped HPLMN SST (1,opt) | Mapped HPLMN SD (3,opt)
							// The length of minimum s-nssai comprised of a length and a SST is 2 bytes.

							for len(parameterValue) >= 2 {
								snssaiLength := parameterValue[0]
								snssaiValue := parameterValue[1:]

								if len(snssaiValue) < int(snssaiLength) {
									ikeLog.Error("SNSSAI length error")
									return 0, nil, nil, errors.New("Error formatting")
								} else {
									snssaiValue = snssaiValue[:snssaiLength]
								}

								ngapSNSSAIItem := ngapType.AllowedNSSAIItem{}

								if len(snssaiValue) == 1 {
									ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
										SST: ngapType.SST{
											Value: []byte{snssaiValue[0]},
										},
									}
								} else if len(snssaiValue) == 4 {
									ngapSNSSAIItem.SNSSAI = ngapType.SNSSAI{
										SST: ngapType.SST{
											Value: []byte{snssaiValue[0]},
										},
										SD: &ngapType.SD{
											Value: []byte{snssaiValue[1], snssaiValue[2], snssaiValue[3]},
										},
									}
								} else {
									ikeLog.Error("Empty SNSSAI value")
									return 0, nil, nil, errors.New("Error formatting")
								}

								ngapNSSAI.List = append(ngapNSSAI.List, ngapSNSSAIItem)

								ikeLog.Debugf("Unmarshal SNSSAI: % x", parameterValue[:1+snssaiLength])
								ikeLog.Debugf("\t\t\tSST: % x", ngapSNSSAIItem.SNSSAI.SST.Value)
								sd := ngapSNSSAIItem.SNSSAI.SD
								if sd == nil {
									ikeLog.Debugf("\t\t\tSD: nil")
								} else {
									ikeLog.Debugf("\t\t\tSD: % x", sd.Value)
								}

								// shift parameterValue for parsing next s-nssai
								parameterValue = parameterValue[1+snssaiLength:]
							}
							anParameters.RequestedNSSAI = ngapNSSAI
						} else {
							ikeLog.Warn("AN-Parameter NSSAI is empty")
						}
					case message.ANParametersTypeEstablishmentCause:
						ikeLog.Debugf("-> Parameter type: ANParametersTypeEstablishmentCause")
						if parameterLength != 0 {
							parameterValue := anParameterField[2:]

							if len(parameterValue) < int(parameterLength) {
								return 0, nil, nil, errors.New("Error formatting")
							} else {
								parameterValue = parameterValue[:parameterLength]
							}

							if len(parameterValue) != message.ANParametersLenEstCause {
								return 0, nil, nil, errors.New("Unmatched Establishment Cause length")
							}

							ikeLog.Debugf("Unmarshal ANParametersTypeEstablishmentCause: % x", parameterValue)

							establishmentCause := parameterValue[0] & 0x0f
							switch establishmentCause {
							case message.EstablishmentCauseEmergency:
								ikeLog.Trace("AN-Parameter establishment cause: Emergency")
							case message.EstablishmentCauseHighPriorityAccess:
								ikeLog.Trace("AN-Parameter establishment cause: High Priority Access")
							case message.EstablishmentCauseMO_Signalling:
								ikeLog.Trace("AN-Parameter establishment cause: MO Signalling")
							case message.EstablishmentCauseMO_Data:
								ikeLog.Trace("AN-Parameter establishment cause: MO Data")
							case message.EstablishmentCauseMPS_PriorityAccess:
								ikeLog.Trace("AN-Parameter establishment cause: MPS Priority Access")
							case message.EstablishmentCauseMCS_PriorityAccess:
								ikeLog.Trace("AN-Parameter establishment cause: MCS Priority Access")
							default:
								ikeLog.Trace("AN-Parameter establishment cause: Unknown. Treat as mo-Data")
								establishmentCause = message.EstablishmentCauseMO_Data
							}

							ngapEstablishmentCause := new(ngapType.RRCEstablishmentCause)
							ngapEstablishmentCause.Value = aper.Enumerated(establishmentCause)

							anParameters.EstablishmentCause = ngapEstablishmentCause
						} else {
							ikeLog.Warn("AN-Parameter establishment cause field empty")
						}
					default:
						ikeLog.Warn("Unsopprted AN-Parameter. Ignore.")
					}

					// shift anParameterField
					anParameterField = anParameterField[2+parameterLength:]
				}
			}

			// shift codedData
			codedData = codedData[2+anParameterLength:]
		} else {
			ikeLog.Error("No AN-Parameter type or length specified")
			return 0, nil, nil, errors.New("Error formatting")
		}

		if len(codedData) >= 2 {
			// Length of the NASPDU field
			nasPDULength := binary.BigEndian.Uint16(codedData[:2])
			ikeLog.Debugf("nasPDULength: %d", nasPDULength)

			if nasPDULength != 0 {
				nasPDUField := codedData[2:]

				// Bound checking
				if len(nasPDUField) < int(nasPDULength) {
					return 0, nil, nil, errors.New("Error formatting")
				} else {
					nasPDUField = nasPDUField[:nasPDULength]
				}

				ikeLog.Debugf("nasPDUField: % v", nasPDUField)

				nasPDU = append(nasPDU, nasPDUField...)
			} else {
				ikeLog.Error("No NAS PDU included in EAP-5G packet")
				return 0, nil, nil, errors.New("No NAS PDU")
			}
		} else {
			ikeLog.Error("No NASPDU length specified")
			return 0, nil, nil, errors.New("Error formatting")
		}

		return
	} else {
		return 0, nil, nil, errors.New("No data to decode")
	}
}
