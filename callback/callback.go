/**
 * @Author: fuxiao
 * @Author: 576101059@qq.com
 * @Date: 2021/5/27 14:24
 * @Desc: TODO
 */

package callback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	commandStateChange               = "State.StateChange"
	commandBeforeFriendAdd           = "Sns.CallbackPrevFriendAdd"
	commandBeforeFriendResponse      = "Sns.CallbackPrevFriendResponse"
	commandAfterFriendAdd            = "Sns.CallbackFriendAdd"
	commandAfterFriendDelete         = "Sns.CallbackFriendDelete"
	commandAfterBlacklistAdd         = "Sns.CallbackBlackListAdd"
	commandAfterBlacklistDelete      = "Sns.CallbackBlackListDelete"
	commandBeforePrivateMessageSend  = "C2C.CallbackBeforeSendMsg"
	commandAfterPrivateMessageSend   = "C2C.CallbackAfterSendMsg"
	commandAfterPrivateMessageReport = "C2C.CallbackAfterMsgReport"
	commandAfterPrivateMessageRevoke = "C2C.CallbackAfterMsgWithDraw"
	commandBeforeGroupCreate         = "Group.CallbackBeforeCreateGroup"
	commandAfterGroupCreate          = "Group.CallbackAfterCreateGroup"
	commandBeforeApplyJoinGroup      = "Group.CallbackBeforeApplyJoinGroup"
	commandBeforeInviteJoinGroup     = "Group.CallbackBeforeInviteJoinGroup"
	commandAfterNewMemberJoinGroup   = "Group.CallbackAfterNewMemberJoin"
	commandAfterMemberExitGroup      = "Group.CallbackAfterMemberExit"
	commandBeforeGroupMessageSend    = "Group.CallbackBeforeSendMsg"
	commandAfterGroupMessageSend     = "Group.CallbackAfterSendMsg"
	commandAfterGroupFull            = "Group.CallbackAfterGroupFull"
	commandAfterGroupDestroyed       = "Group.CallbackAfterGroupDestroyed"
	commandAfterGroupInfoChanged     = "Group.CallbackAfterGroupInfoChanged"
)

const (
	EventStateChange Event = iota + 1
	EventBeforeFriendAdd
	EventBeforeFriendResponse
	EventAfterFriendAdd
	EventAfterFriendDelete
	EventAfterBlacklistAdd
	EventAfterBlacklistDelete
	EventBeforePrivateMessageSend
	EventAfterPrivateMessageSend
	EventAfterPrivateMessageReport
	EventAfterPrivateMessageRevoke
	EventBeforeGroupCreate
	EventAfterGroupCreate
	EventBeforeApplyJoinGroup
	EventBeforeInviteJoinGroup
	EventAfterNewMemberJoinGroup
	EventAfterMemberExitGroup
	EventBeforeGroupMessageSend
	EventAfterGroupMessageSend
	EventAfterGroupFull
	EventAfterGroupDestroyed
	EventAfterGroupInfoChanged
)

const (
	ackSuccessStatus = "OK"
	ackFailureStatus = "FAIL"

	ackSuccessCode = 0
	ackFailureCode = 1

	queryAppId           = "SdkAppid"
	queryCommand         = "CallbackCommand"
	querySignRequestTime = "RequestTime"
	querySign            = "Sign"
	queryClientId        = "ClientIP"
	queryOptPlatform     = "OptPlatform"
	queryContentType     = "contenttype"
)

type (
	Event            int
	EventHandlerFunc func(ctx context.Context, ack Ack, data interface{})
	Options          struct {
		SdkAppId int
	}

	Callback interface {
		// Register 注册事件
		Register(event Event, handler EventHandlerFunc)
		// Listen 监听事件
		Listen(ctx context.Context, w http.ResponseWriter, r *http.Request)
	}

	callback struct {
		appId    int
		token    string
		mu       sync.Mutex
		handlers map[Event]EventHandlerFunc
	}

	Ack interface {
		// Ack 应答
		Ack(resp interface{}) error
		// AckFailure 失败应答
		AckFailure(message ...string) error
		// AckSuccess 成功应答
		AckSuccess(code int, message ...string) error
	}

	ack struct {
		w http.ResponseWriter
	}
)

func NewCallback(appId int, token ...string) Callback {
	ca := &callback{
		appId:    appId,
		handlers: make(map[Event]EventHandlerFunc),
	}
	if len(token) > 0 {
		ca.token = token[0]
	}
	return ca
}

// CallBackSignCheck 回调校验
// 参照说明地址：https://cloud.tencent.com/document/product/269/32431#.E5.9F.BA.E7.A1.80.E5.9B.9E.E8.B0.83.E9.85.8D.E7.BD.AE?from_cn_redirect=1
// 签名的算法为sha256(token + requestTime)
func (c *callback) signCheck(sign string, requestTime int64, token string) error {
	// 检查时间戳是否在有效期内(1分钟)
	now := time.Now().Unix()
	if abs(now-requestTime) >= 60 {
		return errors.New("request time expired")
	}
	// 生成对比的签名
	data := token + strconv.FormatInt(requestTime, 10)
	hash := sha256.New()
	hash.Write([]byte(data))
	signStr := hex.EncodeToString(hash.Sum(nil))
	// 对比签名是否一致
	if sign != signStr {
		return errors.New("invalid signature")
	}
	return nil
}

// abs 返回绝对值
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// Register 注册事件
func (c *callback) Register(event Event, handler EventHandlerFunc) {
	c.mu.Lock()
	c.handlers[event] = handler
	c.mu.Unlock()
}

// Listen 监听事件
func (c *callback) Listen(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	a := newAck(w)
	// 校验签名
	if c.token != "" {
		sign, ok := c.GetQuery(r, querySign)
		if !ok {
			_ = a.AckFailure("invalid sign")
			return
		}
		requestTime, ok := c.GetQuery(r, querySignRequestTime)
		if !ok {
			_ = a.AckFailure("invalid request time")
			return
		}
		requestTimeInt, err := strconv.ParseInt(requestTime, 10, 64)
		if err != nil {
			_ = a.AckFailure("parse request time err")
			return
		}
		if err = c.signCheck(sign, requestTimeInt, c.token); err != nil {
			_ = a.AckFailure(err.Error())
			return
		}
	}
	appId, ok := c.GetQuery(r, queryAppId)
	if !ok || appId != strconv.Itoa(c.appId) {
		_ = a.AckFailure("invalid sdk appId")
		return
	}

	command, ok := c.GetQuery(r, queryCommand)
	if !ok {
		_ = a.AckFailure("invalid callback command")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		_ = a.AckFailure(err.Error())
		return
	}

	if event, data, err := c.parseCommand(command, body); err != nil {
		_ = a.AckFailure(err.Error())
	} else {
		if fn, ok := c.handlers[event]; ok {
			fn(ctx, a, data)
			return
		} else {
			_ = a.AckSuccess(ackSuccessCode)
		}
	}
}

// parseCommand parse command and body package.
func (c *callback) parseCommand(command string, body []byte) (event Event, data interface{}, err error) {
	switch command {
	case commandStateChange:
		event = EventStateChange
		data = &StateChange{}
	case commandBeforeFriendAdd:
		event = EventBeforeFriendAdd
		data = &BeforeFriendAdd{}
	case commandBeforeFriendResponse:
		event = EventBeforeFriendResponse
		data = &BeforeFriendResponse{}
	case commandAfterFriendAdd:
		event = EventAfterFriendAdd
		data = &AfterFriendAdd{}
	case commandAfterFriendDelete:
		event = EventAfterFriendDelete
		data = &AfterFriendDelete{}
	case commandAfterBlacklistAdd:
		event = EventAfterBlacklistAdd
		data = &AfterBlacklistAdd{}
	case commandAfterBlacklistDelete:
		event = EventAfterBlacklistDelete
		data = &AfterBlacklistDelete{}
	case commandBeforePrivateMessageSend:
		event = EventBeforePrivateMessageSend
		data = &BeforePrivateMessageSend{}
	case commandAfterPrivateMessageSend:
		event = EventAfterPrivateMessageSend
		data = &AfterPrivateMessageSend{}
	case commandAfterPrivateMessageReport:
		event = EventAfterPrivateMessageReport
		data = &AfterPrivateMessageReport{}
	case commandAfterPrivateMessageRevoke:
		event = EventAfterPrivateMessageRevoke
		data = &AfterPrivateMessageRevoke{}
	case commandBeforeGroupCreate:
		event = EventBeforeGroupCreate
		data = &BeforeGroupCreate{}
	case commandAfterGroupCreate:
		event = EventAfterGroupCreate
		data = &AfterGroupCreate{}
	case commandBeforeApplyJoinGroup:
		event = EventBeforeApplyJoinGroup
		data = &BeforeApplyJoinGroup{}
	case commandBeforeInviteJoinGroup:
		event = EventBeforeInviteJoinGroup
		data = &BeforeInviteJoinGroup{}
	case commandAfterNewMemberJoinGroup:
		event = EventAfterNewMemberJoinGroup
		data = &AfterNewMemberJoinGroup{}
	case commandAfterMemberExitGroup:
		event = EventAfterMemberExitGroup
		data = &AfterMemberExitGroup{}
	case commandBeforeGroupMessageSend:
		event = EventBeforeGroupMessageSend
		data = &BeforeGroupMessageSend{}
	case commandAfterGroupMessageSend:
		event = EventAfterGroupMessageSend
		data = &AfterGroupMessageSend{}
	case commandAfterGroupFull:
		event = EventAfterGroupFull
		data = &AfterGroupFull{}
	case commandAfterGroupDestroyed:
		event = EventAfterGroupDestroyed
		data = &AfterGroupDestroyed{}
	case commandAfterGroupInfoChanged:
		event = EventAfterGroupInfoChanged
		data = &AfterGroupInfoChanged{}
	default:
		return 0, nil, errors.New("invalid callback command")
	}

	if err = json.Unmarshal(body, &data); err != nil {
		return 0, nil, err
	}

	return event, data, nil
}

// GetQuery 获取查询参数
func (c *callback) GetQuery(r *http.Request, key string) (string, bool) {
	if values, ok := r.URL.Query()[key]; ok {
		return values[0], ok
	} else {
		return "", false
	}
}

func newAck(w http.ResponseWriter) Ack {
	return &ack{w}
}

// Ack 应答
func (a *ack) Ack(resp interface{}) error {
	b, _ := json.Marshal(resp)
	a.w.WriteHeader(http.StatusOK)
	_, err := a.w.Write(b)
	return err
}

// AckFailure 应答失败
func (a *ack) AckFailure(message ...string) error {
	resp := BaseResp{}
	resp.ActionStatus = ackFailureStatus
	resp.ErrorCode = ackFailureCode
	if len(message) > 0 {
		resp.ErrorInfo = message[0]
	}

	return a.Ack(resp)
}

// AckSuccess 应答成功
func (a *ack) AckSuccess(code int, message ...string) error {
	resp := BaseResp{}
	resp.ActionStatus = ackSuccessStatus
	resp.ErrorCode = code
	if len(message) > 0 {
		resp.ErrorInfo = message[0]
	}

	return a.Ack(resp)
}
