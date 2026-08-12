-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

-- YggdraSIM APDU dissector -- Wireshark capability probe.
--
-- Diagnostic only. This file is deliberately NOT shipped in the wheel or
-- the PyInstaller bundle; it exists so an engineer can establish what a
-- given Wireshark build actually offers before trusting the dissector's
-- registration path on that machine.
--
-- Usage:
--   tshark -X lua_script:probe_wireshark_env.lua -r any.pcap
--
-- Every answer is written to stderr prefixed with "PROBE " so the report
-- survives being piped alongside ordinary tshark output.
--
-- IMPORTANT: Wireshark refuses to load -X lua_script: files when the
-- process runs as root, and it does so *silently* -- no error, no warning
-- beyond the generic superuser notice. If this script produces no output
-- at all, that is almost certainly why. Re-run as an unprivileged user.

local out = io.stderr

local function report(key, value)
    out:write("PROBE " .. key .. " = " .. tostring(value) .. "\n")
end

report("wireshark_version", get_version())

-- The registration surface the dissector depends on. When this table is
-- absent the dissector cannot bind to GSMTAP SIM frames by type and has
-- to fall back to a udp.port registration.
local table_ok, gsmtap_types = pcall(DissectorTable.get, "gsmtap.type")
report("dissector_table.gsmtap.type", table_ok and tostring(gsmtap_types) or "ABSENT")

-- Field extractors must be constructed at file scope. Constructing one
-- inside a dissector raises "A Field extractor must be defined before
-- Taps or Dissectors get called", so the probe builds them here.
local probed_fields = {
    "gsmtap.version",
    "gsmtap.hdr_len",
    "gsmtap.type",
    "gsmtap.sub_type",
    "gsmtap.arfcn",
    "gsmtap.uplink",
}
local extractors = {}
for _, name in ipairs(probed_fields) do
    local field_ok, handle = pcall(Field.new, name)
    report("field." .. name, field_ok and "available" or "ABSENT")
    if field_ok then
        extractors[name] = handle
    end
end

-- Chaining to the stock dissector is what lets the deep tree coexist with
-- the 242 gsm_sim.* fields instead of displacing them.
local gsm_sim = Dissector.get("gsm_sim")
report("dissector.gsm_sim", gsm_sim ~= nil and tostring(gsm_sim) or "ABSENT")

for _, capability in ipairs({ "ProtoExpert", "Pref", "ByteArray", "TvbRange" }) do
    report("global." .. capability, _G[capability] ~= nil and "available" or "ABSENT")
end

local probe_proto = Proto("yggdrasim_apdu_probe", "YggdraSIM APDU Probe")
local f_payload_len = ProtoField.uint32(
    "yggdrasim_apdu_probe.payload_len",
    "Payload length",
    base.DEC
)
probe_proto.fields = { f_payload_len }

local reported_first_frame = false

function probe_proto.dissector(payload, pinfo, tree)
    if reported_first_frame == false then
        reported_first_frame = true
        -- ``offset`` tells us where the payload sits inside the frame,
        -- which is how we confirm the GSMTAP header was stripped before
        -- dispatch (Ethernet 14 + IPv4 20 + UDP 8 + GSMTAP 16 = 58).
        local offset_ok, offset = pcall(function()
            return payload:offset()
        end)
        report("payload.offset_in_frame", offset_ok and offset or "UNAVAILABLE")
        report("payload.length", payload:len())
        local type_handle = extractors["gsmtap.type"]
        if type_handle ~= nil then
            local field_info = type_handle()
            report("payload.gsmtap_type", field_info ~= nil and field_info.value or "nil")
        end
    end
    tree:add(probe_proto, payload(0, 0), "YggdraSIM APDU probe")
        :add(f_payload_len, payload:len())
end

if table_ok and gsmtap_types ~= nil then
    -- 0x04 is GSMTAP_TYPE_SIM (Tools/HilBridge/protocol.py:32).
    gsmtap_types:add(0x04, probe_proto)
    report("registration.gsmtap_type_0x04", "registered")
else
    report("registration.gsmtap_type_0x04", "SKIPPED -- table unavailable")
end
