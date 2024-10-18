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
	"unicode"
)

type MessageParserState uint8
type MessageType byte

const MessageDataStartIndex = 5

const (
	MessageTypeStartup         MessageType = '\x00'
	MessageTypeSSLRequest                  = '\x01'
	MessageTypeGSSENCRequest               = '\x02'
	MessageTypeAuthentication              = 'R'
	MessageTypeParameterStatus             = 'S'
	MessageTypeQuery                       = 'Q'
	MessageTypeReadyForQuery               = 'Z'
	MessageTypeTerminate                   = 'X'
	MessageTypeNotice                      = 'N'
)

func (m MessageType) String() string {
	switch m {
	case MessageTypeStartup:
		return "Startup(0)"
	case MessageTypeSSLRequest:
		return "SSLRequest(1)"
	case MessageTypeAuthentication:
		return "Authentication(R)"
	case MessageTypeParameterStatus:
		return "ParameterStatus(S)"
	case MessageTypeQuery:
		return "Query(Q)"
	case MessageTypeReadyForQuery:
		return "ReadyForQuery(Z)"
	case MessageTypeTerminate:
		return "Terminate(X)"
	case MessageTypeNotice:
		return "MessageTypeNotice(N)"
	default:
		return "MessageType(" + string(m) + ")"
	}
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

type ConnectionParams map[string]string

type StartupMessageParsed struct {
	// TODO: parse other things like protocol
	Params ConnectionParams
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

func (m *Message) ParseStartupParameters() (StartupMessageParsed, error) {
	// parameters start after 4 bytes of packet length + 4 bytes of protocol version
	ps := m.Data[8:]

	var parsed StartupMessageParsed
	parsed.Params = make(map[string]string)

	j := 0
	key := ""
	value := ""
	state := 0 // 0 = parsing key, 1 = parsing value
	for i, c := range ps {
		if c == 0 {
			str := string(ps[j:i])

			if state == 0 {
				key = str
				state++
			} else {
				value = str
				parsed.Params[key] = value
				state--
			}

			j = i + 1
		}
	}

	return parsed, nil
}

func ReadMessage(reader *bufio.Reader) (*Message, error) {
	var message Message
	var err error

	firstByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// I have NO idea if this is the right way to do this, it feels so hacky to me, but I'm not
	// sure how else to differentiate between typeless and typed packets.  I thought about having
	// something like a "parser state" (since startup messages will only come at the start of the
	// connection, but that doesn't work since the client can ask for an SSL connection AFTER the
	// startup packet in theory.  So for now I'm just exploiting the fact that all typed packets
	// start with bytes in the letter range, and typeless ones start with big endian lengths, so the
	// first byte will not typically be in that range.  Perhaps you could craft a really silly
	// startup message that has just the right length to break this?
	if unicode.IsLetter(rune(firstByte)) {
		// we have a regular message containing the message type in the startup byte
		message.Type = MessageType(firstByte)
		messageLen, err := readMessageLength(reader)
		if err != nil {
			return nil, fmt.Errorf("could not read length bytes: %w", err)
		}

		message.Length = messageLen
		message.Data = make([]byte, messageLen+1) // +1 for the type byte

		message.Data[0] = firstByte
		binary.BigEndian.PutUint32(message.Data[1:5], messageLen)
		_, err = io.ReadFull(reader, message.Data[5:])
		if err != nil {
			return nil, fmt.Errorf("could not read message: %w", err)
		}

		return &message, nil
	} else {
		// we have one of the weird "no-type-byte" message types like a StartupMessage or an
		// encryption request
		lengthBytes := make([]byte, 4)
		lengthBytes[0] = firstByte
		_, err = io.ReadFull(reader, lengthBytes[1:])
		if err != nil {
			return nil, err
		}

		messageLen := binary.BigEndian.Uint32(lengthBytes)
		message.Length = messageLen

		message.Data = make([]byte, messageLen)
		copy(message.Data, lengthBytes)

		_, err := io.ReadFull(reader, message.Data[4:])
		if err != nil {
			return nil, fmt.Errorf("could not read message: %w", err)
		}

		// now we need to figure out the type:
		if message.Length == 8 {
			// it's an encryption request
			encryptionCode := binary.BigEndian.Uint32(message.Data[4:])
			if encryptionCode == 80877104 {
				message.Type = MessageTypeGSSENCRequest
			} else if encryptionCode == 80877103 {
				message.Type = MessageTypeSSLRequest
			} else {
				return nil, fmt.Errorf("unknown encryption code %d", encryptionCode)
			}
		} else {
			// it's a startup message
			message.Type = MessageTypeStartup
		}

		return &message, nil
	}
}

func readMessageLength(reader *bufio.Reader) (uint32, error) {
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

func NewNotice(msg string) Message {
	buf := make([]byte, 0, MessageDataStartIndex+len(msg)+3)
	packetLen := uint32(cap(buf) - 1)
	buf = append(buf, MessageTypeNotice)
	buf = binary.BigEndian.AppendUint32(buf, packetLen)
	buf = append(buf, 'M') // human readable message
	buf = append(buf, cString(msg)...)
	buf = append(buf, 0) // expects multiple null terminators

	return Message{
		Type:   MessageTypeNotice,
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
