// Implementation of postgres wire protocol message types.
//
// As defined in https://www.postgresql.org/docs/current/protocol-overview.html, postgres messages
// have the following format:
//
// | 1 byte type | 4 byte length | []byte data |
//
// Unfortunately, postgres is not quite that simple, for two reasons:
//
// 1) The message type parameter is duplicated across a number of messages, depending on the state
// of the connection.  For example, the message type byte for both the AuthenticationKerberosV5
// message and the AuthenticationOk message is 'R' for both, and the client is intended to know
// which is which based on the messages that have come before.
//
// 2) Some messages (well, just one, the initial start up message) doesn't have a message type at
// all, and as a server, we are to assume that the first message we receive from the client is a
// startup message
//
// All that to say, the message parser needs to be stateful.
package codec

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

type MessageParserState uint8
type MessageType byte

const MessageDataStartIndex = 5

const (
	ParserStateStartup MessageParserState = iota
	ParserStateRest
)

const (
	MessageTypeStartup         MessageType = '\x00'
	MessageTypeSSLRequest                  = '\x01'
	MessageTypeAuthentication              = 'R'
	MessageTypeParameterStatus             = 'S'
	MessageTypeQuery                       = 'Q'
	MessageTypeReadyForQuery               = 'Z'
	MessageTypeTerminate                   = 'X'
)

func (m MessageType) String() string {
	switch m {
	case MessageTypeStartup:
		return "Startup(0)"
	case MessageTypeAuthentication:
		return "Authentication(R)"
	case MessageTypeParameterStatus:
		return "ParameterStatus(S)"
	case MessageTypeQuery:
		return "Query(Q)"
	case MessageTypeReadyForQuery:
		return "ReadyForQuery(Z)"
	default:
		return "MessageType(" + string(m) + ")"
	}
}

type MessageParser struct {
	state MessageParserState
}

type Message struct {
	Type   MessageType
	Length uint32
	// full Data of message, including length & type
	Data []byte
}

type MessageQueryParsed struct {
	QueryString string
}

// -------------------------------------------------------------------------------------------------
// Client message parsing
// -------------------------------------------------------------------------------------------------

func (m *Message) ParseAsQuery() MessageQueryParsed {
	if m.Type != MessageTypeQuery {
		log.Panicf("ParseAsQuery: expected message type %d, received %d", MessageTypeQuery, m.Type)
	}

	return MessageQueryParsed{
		QueryString: string(m.Data[MessageDataStartIndex:m.Length]),
	}
}

func (m *MessageParser) ReadMessage(reader *bufio.Reader) (*Message, error) {
	var message Message
	var err error

	switch m.state {
	case ParserStateStartup:
		{
			// FIXME: if the client wants to use SSL, then it might start with an SSL request rather
			// than a startup request, but we're just going to pretend that's impossible for now
			message.Type = MessageTypeStartup
			// first 4 bytes are the length of message (including self)
			lengthBytes := make([]byte, 4)
			_, err = io.ReadFull(reader, lengthBytes)
			if err != nil {
				return nil, fmt.Errorf("could not read length bytes: %w", err)
			}

			messageLen := binary.BigEndian.Uint32(lengthBytes)
			message.Length = messageLen

			// It's an SSL request...this feels hacky but I'm not sure how else to do it
			if message.Length == 8 {
				message.Type = MessageTypeSSLRequest
			} else {
				message.Type = MessageTypeStartup
				m.state = ParserStateRest
			}

			// question: I'm not sure if using `make` here (and following) is really the best way to
			// do things, or if I'm supposed to be just creating an array...it seems like with the
			// gc it shouldn't really matter a lot?
			message.Data = make([]byte, messageLen)
			copy(message.Data, lengthBytes)

			_, err := io.ReadFull(reader, message.Data[4:])
			if err != nil {
				return nil, fmt.Errorf("could not read message: %w", err)
			}

			return &message, nil
		}
	case ParserStateRest:
		{
			typeByte, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}

			message.Type = MessageType(typeByte)
			messageLen, err := m.readMessageLength(reader)
			if err != nil {
				return nil, fmt.Errorf("could not read length bytes: %w", err)
			}

			message.Length = messageLen
			message.Data = make([]byte, messageLen+1) // +1 for the type byte

			message.Data[0] = typeByte
			binary.BigEndian.PutUint32(message.Data[1:5], messageLen)
			_, err = io.ReadFull(reader, message.Data[5:])
			if err != nil {
				return nil, fmt.Errorf("could not read message: %w", err)
			}

			return &message, nil
		}
	default:
		return nil, fmt.Errorf("ReadMessage: invalid state %d", m.state)
	}
}

func (m *MessageParser) readMessageLength(reader *bufio.Reader) (uint32, error) {
	lengthBytes := make([]byte, 4)
	_, err := io.ReadFull(reader, lengthBytes)
	if err != nil {
		return 0, fmt.Errorf("could not read length bytes: %w", err)
	}

	messageLen := binary.BigEndian.Uint32(lengthBytes)
	return messageLen, nil
}

// -------------------------------------------------------------------------------------------------
// Server message encoding
// -------------------------------------------------------------------------------------------------

func NewAuthenticationOkMessage() Message {
	// type + length + int32(0)
	buf := make([]byte, 0, 9)

	// packet length does not ever include the type byte
	packetLen := uint32(cap(buf) - 1)

	buf = append(buf, MessageTypeAuthentication)
	buf = binary.BigEndian.AppendUint32(buf, packetLen)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return Message{
		Type:   MessageTypeAuthentication,
		Length: packetLen,
		Data:   buf,
	}
}

type BackendTransactionStatus byte

const (
	BackendTransactionStatusIdle          = 'I'
	BackendTransactionStatusInTransaction = 'T'
	BackendTransactionStatusFailed        = 'E'
)

func NewReadyForQueryMessage(status BackendTransactionStatus) Message {
	// type + length + byte(status)
	buf := make([]byte, 0, 6)
	buf = append(buf, MessageTypeReadyForQuery)
	packetLen := uint32(cap(buf) - 1)

	buf = binary.BigEndian.AppendUint32(buf, packetLen)
	buf = append(buf, byte(status))

	return Message{
		Type:   MessageTypeReadyForQuery,
		Length: packetLen,
		Data:   buf,
	}
}

func NewParameterStatus(key string, value string) Message {
	buf := make([]byte, 0, MessageDataStartIndex+len(key)+len(value)+2)
	packetLen := uint32(cap(buf) - 1)

	buf = append(buf, MessageTypeParameterStatus)
	buf = binary.BigEndian.AppendUint32(buf, packetLen)

	buf = append(buf, cString(key)...)
	buf = append(buf, cString(value)...)

	return Message{
		Type:   MessageTypeParameterStatus,
		Length: packetLen,
		Data:   buf,
	}
}

func cString(s string) []byte {
	str := make([]byte, len(s)+1)

	copy(str, []byte(s))
	str[len(s)] = 0

	return str
}

// I'm not sure that this is the right way to do these operations, but binary/encoding doesn't have
// methods for signed integers out of the box
func appendInt16(b []byte, v int16) []byte {
	return appendSignedInt(b, v, 2)
}

func readInt16(b []byte) int16 {
	return readSignedInt[int16](b, 2)
}

func appendInt32(b []byte, v int32) []byte {
	return appendSignedInt(b, v, 4)
}

func readInt32(b []byte) int32 {
	return readSignedInt[int32](b, 4)
}

type sizedSignedInteger interface {
	~int8 | ~int16 | ~int32 | ~int64
}

func appendSignedInt[K sizedSignedInteger](b []byte, v K, size int) []byte {
	writer := new(bytes.Buffer)
	err := binary.Write(writer, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}

	t := make([]byte, size)
	n, err := writer.Read(t)
	if n != size || err != nil {
		panic(fmt.Errorf("unexpected writer.Read, read = %d, err = %v", n, err))
	}

	return append(b, t...)
}

func readSignedInt[K sizedSignedInteger](b []byte, size int) K {
	if len(b) < size {
		// FIXME: it would be really nice if this printed the type name of K
		panic(fmt.Errorf("at least %d bytes required to parse int", size))
	}

	var v K
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.BigEndian, &v)
	if err != nil {
		panic(err)
	}

	return v
}
