package slack

import (
	"context"
	"fmt"

	slackgo "github.com/slack-go/slack"
)

// SlackGoClient is a Client implementation backed by github.com/slack-go/slack.
// It is a thin translation layer between the adapter's neutral types and the
// concrete slack-go API surface. Use NewSlackGoClient to construct it.
type SlackGoClient struct {
	api *slackgo.Client
}

// NewSlackGoClient wraps a *slackgo.Client. Pass nil for opts if no custom
// options are required.
func NewSlackGoClient(token string, opts ...slackgo.Option) *SlackGoClient {
	return &SlackGoClient{api: slackgo.New(token, opts...)}
}

// PostMessage translates a PostOptions to slack-go's MsgOption chain.
func (c *SlackGoClient) PostMessage(ctx context.Context, channelID string, opts PostOptions) (PostResult, error) {
	msgOpts := []slackgo.MsgOption{}
	if opts.Text != "" {
		msgOpts = append(msgOpts, slackgo.MsgOptionText(opts.Text, false))
	}
	if len(opts.Blocks) > 0 {
		msgOpts = append(msgOpts, slackgo.MsgOptionBlocks(toSlackGoBlocks(opts.Blocks)...))
	}
	if opts.ThreadTS != "" {
		msgOpts = append(msgOpts, slackgo.MsgOptionTS(opts.ThreadTS))
	}

	respChan, respTS, err := c.api.PostMessageContext(ctx, channelID, msgOpts...)
	if err != nil {
		return PostResult{}, err
	}
	return PostResult{
		ChannelID: respChan,
		Timestamp: respTS,
	}, nil
}

// GetReactions returns all reactions on a message via the conversations.history-
// adjacent reactions.get endpoint.
func (c *SlackGoClient) GetReactions(ctx context.Context, channelID string, ts string) ([]Reaction, error) {
	reactions, err := c.api.GetReactionsContext(ctx, slackgo.ItemRef{
		Channel:   channelID,
		Timestamp: ts,
	}, slackgo.GetReactionsParameters{Full: true})
	if err != nil {
		return nil, err
	}
	out := make([]Reaction, 0, len(reactions))
	for _, r := range reactions {
		out = append(out, Reaction{
			Name:  r.Name,
			Users: r.Users,
			Count: r.Count,
		})
	}
	return out, nil
}

// GetThreadReplies returns the parent message followed by replies.
func (c *SlackGoClient) GetThreadReplies(ctx context.Context, channelID string, parentTS string) ([]ThreadMessage, error) {
	params := &slackgo.GetConversationRepliesParameters{
		ChannelID: channelID,
		Timestamp: parentTS,
	}
	msgs, _, _, err := c.api.GetConversationRepliesContext(ctx, params)
	if err != nil {
		return nil, err
	}
	out := make([]ThreadMessage, 0, len(msgs))
	for i, m := range msgs {
		out = append(out, ThreadMessage{
			User:      m.User,
			Text:      m.Text,
			Timestamp: m.Timestamp,
			IsParent:  i == 0,
		})
	}
	return out, nil
}

// LookupUser returns the minimal user profile.
func (c *SlackGoClient) LookupUser(ctx context.Context, userID string) (UserProfile, error) {
	u, err := c.api.GetUserInfoContext(ctx, userID)
	if err != nil {
		return UserProfile{}, err
	}
	name := u.RealName
	if name == "" {
		name = u.Name
	}
	return UserProfile{
		ID:          u.ID,
		DisplayName: name,
		Email:       u.Profile.Email,
	}, nil
}

// toSlackGoBlocks converts our neutral Block representation into the
// slack-go MessageBlock slice. Limited to the block kinds DefaultRender emits.
func toSlackGoBlocks(blocks []Block) []slackgo.Block {
	out := make([]slackgo.Block, 0, len(blocks))
	for _, b := range blocks {
		switch b.Kind {
		case BlockHeader:
			out = append(out, slackgo.NewHeaderBlock(slackgo.NewTextBlockObject("plain_text", b.Text, false, false)))
		case BlockSection:
			out = append(out, slackgo.NewSectionBlock(slackgo.NewTextBlockObject("mrkdwn", b.Text, false, false), nil, nil))
		case BlockDivider:
			out = append(out, slackgo.NewDividerBlock())
		case BlockContext:
			var elements []slackgo.MixedElement
			for _, e := range b.Elements {
				elements = append(elements, slackgo.NewTextBlockObject("mrkdwn", e, false, false))
			}
			out = append(out, slackgo.NewContextBlock("", elements...))
		case BlockActions:
			var els []slackgo.BlockElement
			for _, btn := range b.Buttons {
				txt := slackgo.NewTextBlockObject("plain_text", btn.Label, false, false)
				if btn.URL != "" {
					// Link button (uses Button with URL).
					be := slackgo.NewButtonBlockElement(btn.ActionID, "", txt)
					be.URL = btn.URL
					els = append(els, be)
				} else {
					be := slackgo.NewButtonBlockElement(btn.ActionID, btn.ActionID, txt)
					if btn.Style == "primary" {
						be.Style = slackgo.StylePrimary
					} else if btn.Style == "danger" {
						be.Style = slackgo.StyleDanger
					}
					els = append(els, be)
				}
			}
			out = append(out, slackgo.NewActionBlock("", els...))
		default:
			// Unknown kind — render as a plain section to keep the message visible.
			out = append(out, slackgo.NewSectionBlock(slackgo.NewTextBlockObject("mrkdwn", fmt.Sprintf("_(unknown block: %s)_", b.Kind), false, false), nil, nil))
		}
	}
	return out
}

// Compile-time check that SlackGoClient satisfies the Client interface.
var _ Client = (*SlackGoClient)(nil)
