/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net"
)

const (
	IPv4offsetTotalLength = 2
	IPv4offsetSrc         = 12
	IPv4offsetDst         = IPv4offsetSrc + net.IPv4len
)
const (
	TCPoffsetSrcPort = IPv4offsetDst + net.IPv4len
	TCPoffsetDstPort = TCPoffsetSrcPort + 2
)

const (
	IPv6offsetPayloadLength = 4
	IPv6offsetSrc           = 8
	IPv6offsetDst           = IPv6offsetSrc + net.IPv6len
)
