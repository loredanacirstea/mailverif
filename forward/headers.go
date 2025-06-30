package forward

import "strings"

// all email headers
const (
	HEADER_FROM        = "From"
	HEADER_TO          = "To"
	HEADER_CC          = "Cc"
	HEADER_BCC         = "Bcc"
	HEADER_REPLY_TO    = "Reply-To"
	HEADER_SENDER      = "Sender"
	HEADER_RETURN_PATH = "Return-Path"

	HEADER_DATE        = "Date"
	HEADER_MESSAGE_ID  = "Message-ID"
	HEADER_IN_REPLY_TO = "In-Reply-To"
	HEADER_REFERENCES  = "References"

	HEADER_SUBJECT                   = "Subject"
	HEADER_CONTENT_TYPE              = "Content-Type"
	HEADER_CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding"
	HEADER_MIME_VERSION              = "MIME-Version"

	HEADER_DKIM_SIGNATURE             = "DKIM-Signature"
	HEADER_ARC_SEAL                   = "ARC-Seal"
	HEADER_ARC_MESSAGE_SIGNATURE      = "ARC-Message-Signature"
	HEADER_ARC_AUTHENTICATION_RESULTS = "ARC-Authentication-Results"
	HEADER_AUTHENTICATION_RESULTS     = "Authentication-Results"
	HEADER_RECEIVED                   = "Received"
	HEADER_RECEIVED_SPF               = "Received-SPF"
	HEADER_DELIVERED_TO               = "Delivered-To"

	// additional
	HEADER_USER_AGENT              = "User-Agent"
	HEADER_X_MAILER                = "X-Mailer"
	HEADER_X_ORIGINATING_IP        = "X-Originating-IP"
	HEADER_X_GOOGLE_DKIM_SIGNATURE = "X-Google-DKIM-Signature"
	HEADER_X_GM_MESSAGE_STATE      = "X-Gm-Message-State"
	HEADER_X_FORWARDED_FOR         = "X-Forwarded-For"
	HEADER_X_FORWARDED_TO          = "X-Forwarded-To"
	HEADER_X_FORWARDED_ENCRYPTED   = "X-Forwarded-Encrypted"
)

var (
	HEADER_LOW_FROM        = strings.ToLower(HEADER_FROM)
	HEADER_LOW_TO          = strings.ToLower(HEADER_TO)
	HEADER_LOW_CC          = strings.ToLower(HEADER_CC)
	HEADER_LOW_BCC         = strings.ToLower(HEADER_BCC)
	HEADER_LOW_REPLY_TO    = strings.ToLower(HEADER_REPLY_TO)
	HEADER_LOW_SENDER      = strings.ToLower(HEADER_SENDER)
	HEADER_LOW_RETURN_PATH = strings.ToLower(HEADER_RETURN_PATH)

	HEADER_LOW_DATE        = strings.ToLower(HEADER_DATE)
	HEADER_LOW_MESSAGE_ID  = strings.ToLower(HEADER_MESSAGE_ID)
	HEADER_LOW_IN_REPLY_TO = strings.ToLower(HEADER_IN_REPLY_TO)
	HEADER_LOW_REFERENCES  = strings.ToLower(HEADER_REFERENCES)

	HEADER_LOW_SUBJECT                   = strings.ToLower(HEADER_SUBJECT)
	HEADER_LOW_CONTENT_TYPE              = strings.ToLower(HEADER_CONTENT_TYPE)
	HEADER_LOW_CONTENT_TRANSFER_ENCODING = strings.ToLower(HEADER_CONTENT_TRANSFER_ENCODING)
	HEADER_LOW_MIME_VERSION              = strings.ToLower(HEADER_MIME_VERSION)

	HEADER_LOW_DKIM_SIGNATURE             = strings.ToLower(HEADER_DKIM_SIGNATURE)
	HEADER_LOW_ARC_SEAL                   = strings.ToLower(HEADER_ARC_SEAL)
	HEADER_LOW_ARC_MESSAGE_SIGNATURE      = strings.ToLower(HEADER_ARC_MESSAGE_SIGNATURE)
	HEADER_LOW_ARC_AUTHENTICATION_RESULTS = strings.ToLower(HEADER_ARC_AUTHENTICATION_RESULTS)
	HEADER_LOW_AUTHENTICATION_RESULTS     = strings.ToLower(HEADER_AUTHENTICATION_RESULTS)
	HEADER_LOW_RECEIVED                   = strings.ToLower(HEADER_RECEIVED)
	HEADER_LOW_RECEIVED_SPF               = strings.ToLower(HEADER_RECEIVED_SPF)
	HEADER_LOW_DELIVERED_TO               = strings.ToLower(HEADER_DELIVERED_TO)

	// additional
	HEADER_LOW_USER_AGENT              = strings.ToLower(HEADER_USER_AGENT)
	HEADER_LOW_X_MAILER                = strings.ToLower(HEADER_X_MAILER)
	HEADER_LOW_X_ORIGINATING_IP        = strings.ToLower(HEADER_X_ORIGINATING_IP)
	HEADER_LOW_X_GOOGLE_DKIM_SIGNATURE = strings.ToLower(HEADER_X_GOOGLE_DKIM_SIGNATURE)
	HEADER_LOW_X_GM_MESSAGE_STATE      = strings.ToLower(HEADER_X_GM_MESSAGE_STATE)
	HEADER_LOW_X_FORWARDED_FOR         = strings.ToLower(HEADER_X_FORWARDED_FOR)
	HEADER_LOW_X_FORWARDED_TO          = strings.ToLower(HEADER_X_FORWARDED_TO)
	HEADER_LOW_X_FORWARDED_ENCRYPTED   = strings.ToLower(HEADER_X_FORWARDED_ENCRYPTED)
)
