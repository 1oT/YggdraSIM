# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Physical card transport: PCSC and serial backend abstraction for C-APDU / R-APDU exchange."""
from dataclasses import dataclass
from typing import Tuple ,List ,Optional ,Any 


from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils 
from SCP03 .crypto .session import Scp03ResponseProtectionError ,Scp03Session
from yggdrasim_common .card_backend import create_card_connection ,is_simulated_card_backend


@dataclass (frozen =True )
class ApduTransportPolicy :
    """Safety and trace policy for one logical command exchange."""

    max_followups :int =64
    capture_apdu_bytes :bool =False
    retry_wrong_length :bool =True
    follow_response_data :bool =True

    def __post_init__ (self )->None :
        if not 1 <=int (self .max_followups )<=256 :
            raise ValueError ("max_followups must be in range 1..256.")


@dataclass (frozen =True )
class ApduExchangeTrace :
    """One physical command/response pair within a logical exchange."""

    sequence :int
    phase :str
    command_length :int
    wire_command_length :int
    response_length :int
    clear_response_length :int
    sw1 :int
    sw2 :int
    secure_messaging :bool
    response_verified :Optional [bool ]
    command_hex :Optional [str ]=None
    wire_command_hex :Optional [str ]=None
    wire_response_hex :Optional [str ]=None
    clear_response_hex :Optional [str ]=None
    error :Optional [str ]=None


@dataclass (frozen =True )
class ApduTransmitResult :
    """Result and trace for a complete logical APDU exchange."""

    data :bytes
    sw1 :int
    sw2 :int
    trace :Tuple [ApduExchangeTrace ,...]
    session_invalidated :bool =False
    invalidation_reason :Optional [str ]=None

    def as_tuple (self )->Tuple [bytes ,int ,int ]:
        return self .data ,self .sw1 ,self .sw2


class ApduTransportError (RuntimeError ):
    """Local transport/secure-messaging failure with completed trace entries."""

    def __init__ (
    self ,
    message :str ,
    *,
    trace :Tuple [ApduExchangeTrace ,...]=(),
    cause_type :Optional [str ]=None ,
    ):
        super ().__init__ (message )
        self .trace =trace
        self .cause_type =cause_type


class CardTransporter :
    FI_TABLE ={
    0x1 :(372 ,5 ),
    0x2 :(558 ,6 ),
    0x3 :(744 ,8 ),
    0x4 :(1116 ,12 ),
    0x5 :(1488 ,16 ),
    0x6 :(1860 ,20 ),
    0x9 :(512 ,5 ),
    0xA :(768 ,7.5 ),
    0xB :(1024 ,10 ),
    0xC :(1536 ,15 ),
    0xD :(2048 ,20 ),
    }
    DI_TABLE ={
    0x1 :1 ,
    0x2 :2 ,
    0x3 :4 ,
    0x4 :8 ,
    0x5 :16 ,
    0x6 :32 ,
    0x8 :12 ,
    0x9 :20 ,
    }

    @property
    def connection (self )->Optional [Any ]:
        return getattr (self ,"_connection",None )

    @connection .setter
    def connection (self ,value :Optional [Any ])->None :
        previous =getattr (self ,"_connection",None )
        session =getattr (self ,"session",None )
        has_session_state =False
        if session is not None :
            has_session_state =bool (getattr (session ,"is_authenticated",False ))
            has_session_state =has_session_state or bool (
            int (getattr (session ,"ssc",0 )or 0 )
            )
            has_session_state =has_session_state or any (
            bytes (getattr (session ,"chaining_value",b"")or b"")
            )
        if (
            previous is not None
            and previous is not value
            and has_session_state
        ):
            # A Secure Channel is scoped to one card/application session.
            # Replacing the underlying transport must never carry its state
            # over to a different card or reader.
            self ._reset_session_state ()
        self ._connection =value

    def __init__ (self ):
        self .connection :Optional [Any ]=None 
        self .session =Scp03Session ({'kenc':b'','kmac':b'','dek':b''})
        self .verbose =False 
        self .debug =False 
        self .last_trace :Tuple [ApduExchangeTrace ,...]=()
        self .last_error :Optional [str ]=None
        self .last_session_invalidation :Optional [str ]=None
        if not self .connect ():
            raise RuntimeError ("Could not connect to a smart card reader.")

    def connect (self )->bool :
        """Connect to the physical card using the configured PCSC or serial backend."""
        if hasattr (self ,"session"):
            self ._reset_session_state ()
        try :
            self .connection =create_card_connection (reader_index =0 )
            if is_simulated_card_backend ():
                print (f"{Config.Colors.CYAN}[*] CONNECTED (SIMULATED CARD){Config.Colors.ENDC}")
            else :
                print (f"{Config.Colors.CYAN}[*] CONNECTED{Config.Colors.ENDC}")
            return True 
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Connection failed: {e}{Config.Colors.ENDC}")
            self .connection =None 
            return False 

    def disconnect (self ):
        self ._reset_session_state ()
        if self .connection :self .connection .disconnect ()

    def logout (self )->bool :
        if not self .session :return False 
        was_active =bool (self .session .is_authenticated )
        self ._reset_session_state ()
        return was_active 

    def _reset_session_state (self )->None :
        if not self .session :
            return 
        has_method =False 
        if hasattr (self .session ,'reset_state'):
            has_method =True 
        if has_method :
            self .session .reset_state ()
            return 
        self .session .is_authenticated =False 
        if hasattr (self .session ,'chaining_value'):
            self .session .chaining_value =b'\x00'*16 
        if hasattr (self .session ,'ssc'):
            self .session .ssc =0 

    def reset_session_state (self )->None :
        self ._reset_session_state ()

    def reset (self )->bool :
        """Issue a card reset and return the ATR bytes."""
        # A physical reset terminates the Card Session and therefore every
        # Secure Channel Session, regardless of whether reconnect succeeds.
        self ._reset_session_state ()
        if self .connection is None :return self .connect ()
        try :
            self .connection .disconnect ()
            self .connection .connect ()
            return True 
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Reset Error: {e}{Config.Colors.ENDC}")
            return False 

    def get_atr_bytes (self )->bytes :
        """Return the ATR bytes from the most recent reset."""
        if self .connection is None :
            return b""
        try :
            return bytes (self .connection .getATR ())
        except Exception :
            return b""

    @staticmethod
    def _format_atr_bytes (atr_bytes :bytes )->str :
        return " ".join (f"{b:02X}"for b in atr_bytes )

    @classmethod
    def _decode_ta1 (cls ,value :int )->List [str ]:
        lines :List [str ]=[]
        fi_idx =(value >>4 )&0x0F 
        di_idx =value &0x0F 
        fi_entry =cls .FI_TABLE .get (fi_idx )
        di_entry =cls .DI_TABLE .get (di_idx )
        if fi_entry is None or di_entry is None :
            lines .append (f"    TA(1) raw decode unavailable for {value:02X}")
            return lines 

        fi ,fmax =fi_entry 
        di =di_entry 
        etu_cycles =fi /di 
        nominal_rate =(di *4000000 )/fi 
        max_rate =(di *(fmax *1000000 ))/fi 
        lines .append (f"    TA(1) = {value:02X} --> Fi={fi}, Di={di}, {etu_cycles:g} cycles/ETU")
        lines .append (f"      {nominal_rate:g} bits/s at 4 MHz, fMax for Fi = {fmax:g} MHz => {max_rate:g} bits/s")
        return lines

    @staticmethod
    def _decode_ta3 (value :int )->str :
        clock_stop_bits =(value >>6 )&0x03 
        clock_stop ="not supported"
        if clock_stop_bits ==1 :
            clock_stop ="state L"
        if clock_stop_bits ==2 :
            clock_stop ="state H"
        if clock_stop_bits ==3 :
            clock_stop ="no preference"

        classes :List [str ]=[]
        if value &0x01 :
            classes .append ("A 5V")
        if value &0x02 :
            classes .append ("B 3V")
        if value &0x04 :
            classes .append ("C 1.8V")

        class_text ="not indicated"
        if len (classes )>0 :
            class_text ="(3G) " +" ".join (classes )
        return f"  TA(3) = {value:02X} --> Clock stop: {clock_stop} - Class accepted by the card: {class_text}"

    @staticmethod
    def _protocol_label (protocol :int )->str :
        if protocol ==15 :
            return "15 - Global interface bytes following"
        return str (protocol )

    @staticmethod
    def _decode_card_service_data (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Card service data byte: {value:02X}")
        if value &0x80 :
            lines .append ("        - Application selection: by full DF name")
        if value &0x40 :
            lines .append ("        - Application selection: by partial DF name")
        if value &0x20 :
            lines .append ("        - BER-TLV data objects available in EF.DIR")
        if value &0x10 :
            lines .append ("        - EF.DIR and EF.ATR access services: by GET RECORD(s) command")
        if value &0x08 :
            lines .append ("        - Card with MF")
        return lines

    @staticmethod
    def _decode_selection_methods (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Selection methods: {value:02X}")
        if value &0x80 :
            lines .append ("        - DF selection by full DF name")
        if value &0x40 :
            lines .append ("        - DF selection by partial DF name")
        if value &0x20 :
            lines .append ("        - DF selection by path")
        if value &0x10 :
            lines .append ("        - DF selection by file identifier")
        if value &0x08 :
            lines .append ("        - Implicit DF selection")
        if value &0x04 :
            lines .append ("        - Short EF identifier supported")
        if value &0x02 :
            lines .append ("        - Record number supported")
        if value &0x01 :
            lines .append ("        - Record identifier supported")
        return lines 

    @staticmethod
    def _decode_data_coding (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Data coding byte: {value:02X}")
        write_mode ={0 :"one-time write",1 :"proprietary",2 :"OR",3 :"AND"}.get ((value >>5 )&0x03 ,"unknown")
        lines .append (f"        - Behaviour of write functions: {write_mode}")
        ff_rule ="invalid"
        if value &0x10 :
            ff_rule ="valid"
        lines .append (f"        - Value 'FF' for the first byte of BER-TLV tag fields: {ff_rule}")
        unit_power =value &0x0F 
        data_unit =1 <<unit_power 
        lines .append (f"        - Data unit in quartets: {data_unit}")
        return lines 

    @staticmethod
    def _decode_card_capabilities (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Command chaining, length fields and logical channels: {value:02X}")
        assignment_bits =(value >>3 )&0x03
        if assignment_bits ==0x02 :
            lines .append ("        - Logical channel number assignment: by the card")
        elif assignment_bits ==0x01 :
            lines .append ("        - Logical channel number assignment: by the interface device")
        elif assignment_bits ==0x00 :
            lines .append ("        - Logical channels: not supported")
        else :
            lines .append ("        - Logical channel number assignment: RFU coding")
        channel_bits =value &0x07
        max_channels =str (channel_bits +1 )if channel_bits !=0x07 else "8 or more"
        lines .append (f"        - Maximum number of logical channels: {max_channels}")
        if value &0x80 :
            lines .append ("        - Command chaining supported")
        if value &0x40 :
            lines .append ("        - Extended Lc and Le fields supported")
        return lines 

    @classmethod
    def _decode_compact_tlv_historical (cls ,historical :bytes )->List [str ]:
        lines :List [str ]=[]
        if len (historical )==0 :
            return lines 
        category =historical [0 ]
        if category !=0x80 :
            lines .append (f"  Category indicator byte: {category:02X}")
            return lines 

        lines .append ("  Category indicator byte: 80 (compact TLV data object)")
        index =1 
        while index <len (historical ):
            descriptor =historical [index ]
            index +=1 
            if descriptor ==0x00 :
                break 
            tag =(descriptor >>4 )&0x0F 
            length =descriptor &0x0F 
            if index +length >len (historical ):
                remaining =len (historical )-index
                lines .append (
                f"    Malformed compact TLV: tag {tag} declares {length} byte(s), "
                f"only {remaining} remain"
                )
                break 
            value =historical [index :index +length ]
            index +=length 
            if tag ==0x3 and length ==1 :
                lines .append ("    Tag: 3, len: 1 (card service data byte)")
                lines .extend (cls ._decode_card_service_data (value [0 ]))
                continue 
            if tag ==0x7 and length ==3 :
                lines .append ("    Tag: 7, len: 3 (card capabilities)")
                lines .extend (cls ._decode_selection_methods (value [0 ]))
                lines .extend (cls ._decode_data_coding (value [1 ]))
                lines .extend (cls ._decode_card_capabilities (value [2 ]))
                continue 
            if tag ==0x6 :
                lines .append (f"    Tag: 6, len: {length} (pre-issuing data)")
                lines .append (f"      Data: {value.hex().upper()}")
                continue 
            lines .append (f"    Tag: {tag}, len: {length}")
            lines .append (f"      Data: {value.hex().upper()}")
        return lines 

    def describe_atr (self )->List [str ]:
        """Return a human-readable description of the ATR byte string."""
        atr_bytes =self .get_atr_bytes ()
        lines :List [str ]=[]
        if len (atr_bytes )==0 :
            lines .append ("ATR unavailable.")
            return lines 

        lines .append (f"ATR: {self._format_atr_bytes(atr_bytes)}")
        ts =atr_bytes [0 ]
        convention ="Unknown Convention"
        if ts ==0x3B :
            convention ="Direct Convention"
        if ts ==0x3F :
            convention ="Inverse Convention"
        lines .append (f"+ TS = {ts:02X} --> {convention}")

        if len (atr_bytes )<2 :
            return lines 

        t0 =atr_bytes [1 ]
        y =t0 >>4 
        k =t0 &0x0F 
        lines .append (f"+ T0 = {t0:02X}, Y(1): {y:04b}, K: {k} (historical bytes)")

        index =2 
        group =1 
        protocols :List [int ]=[]
        truncated_interface =""
        while True :
            if y &0x1 :
                if index >=len (atr_bytes ):
                    truncated_interface =f"TA({group})"
                    break 
                ta_value =atr_bytes [index ]
                index +=1 
                if group ==1 :
                    lines .extend (self ._decode_ta1 (ta_value ))
                else :
                    if group ==3 :
                        lines .append (self ._decode_ta3 (ta_value ))
                    else :
                        lines .append (f"  TA({group}) = {ta_value:02X}")
            if y &0x2 :
                if index >=len (atr_bytes ):
                    truncated_interface =f"TB({group})"
                    break 
                tb_value =atr_bytes [index ]
                index +=1 
                lines .append (f"  TB({group}) = {tb_value:02X}")
            if y &0x4 :
                if index >=len (atr_bytes ):
                    truncated_interface =f"TC({group})"
                    break 
                tc_value =atr_bytes [index ]
                index +=1 
                lines .append (f"  TC({group}) = {tc_value:02X}")
            if y &0x8 :
                if index >=len (atr_bytes ):
                    truncated_interface =f"TD({group})"
                    break 
                td_value =atr_bytes [index ]
                index +=1 
                next_y =(td_value >>4 )&0x0F 
                protocol =td_value &0x0F 
                protocols .append (protocol )
                protocol_label =self ._protocol_label (protocol )
                lines .append (f"  TD({group}) = {td_value:02X} --> Y(i+1) = {next_y:04b}, Protocol T = {protocol_label} ")
                lines .append ("-----")
                y =next_y 
                group +=1 
                continue 
            break 

        if len (truncated_interface )>0 :
            lines .append (
            f"! ATR truncated: T0/TD chain announces {truncated_interface}, "
            "but no byte is available."
            )
            return lines

        remaining =len (atr_bytes )-index
        historical_length =min (k ,remaining )
        historical =atr_bytes [index :index +historical_length ]
        if len (historical )>0 :
            lines .append (f"+ Historical bytes: {self._format_atr_bytes(historical)}")
            lines .extend (self ._decode_compact_tlv_historical (historical ))
        index +=historical_length

        if historical_length <k :
            lines .append (
            f"! ATR truncated: T0 announces {k} historical byte(s), "
            f"but only {historical_length} are available."
            )
            return lines

        tck_required =any (protocol !=0 for protocol in protocols )
        if tck_required and index >=len (atr_bytes ):
            lines .append ("! ATR truncated: checksum byte TCK is required but missing.")
            return lines

        if tck_required :
            tck =atr_bytes [index ]
            checksum =0 
            for byte in atr_bytes [1 :index +1 ]:
                checksum ^=byte 
            if checksum ==0 :
                lines .append (f"+ TCK = {tck:02X} (correct checksum)")
            else :
                lines .append (f"+ TCK = {tck:02X} (checksum mismatch)")
            index +=1

        if index <len (atr_bytes ):
            trailing =atr_bytes [index :]
            lines .append (
            f"! ATR contains {len(trailing)} unexpected trailing byte(s): "
            f"{self._format_atr_bytes(trailing)}"
            )
        return lines

    @staticmethod
    def _trace_entry (
    *,
    sequence :int ,
    phase :str ,
    command :bytes ,
    wire_command :bytes ,
    wire_response :bytes ,
    clear_response :Optional [bytes ],
    sw1 :int ,
    sw2 :int ,
    secure_messaging :bool ,
    response_verified :Optional [bool ],
    policy :ApduTransportPolicy ,
    error :Optional [str ]=None ,
    )->ApduExchangeTrace :
        capture =bool (policy .capture_apdu_bytes )
        return ApduExchangeTrace (
        sequence =sequence ,
        phase =phase ,
        command_length =len (command ),
        wire_command_length =len (wire_command ),
        response_length =len (wire_response ),
        clear_response_length =len (clear_response )if clear_response is not None else 0 ,
        sw1 =sw1 ,
        sw2 =sw2 ,
        secure_messaging =secure_messaging ,
        response_verified =response_verified ,
        command_hex =command .hex ().upper ()if capture else None ,
        wire_command_hex =wire_command .hex ().upper ()if capture else None ,
        wire_response_hex =wire_response .hex ().upper ()if capture else None ,
        clear_response_hex =(
        clear_response .hex ().upper ()
        if capture and clear_response is not None
        else None
        ),
        error =error ,
        )

    def _exchange_once (
    self ,
    command :bytes ,
    *,
    phase :str ,
    sequence :int ,
    policy :ApduTransportPolicy ,
    trace :List [ApduExchangeTrace ],
    )->Tuple [bytes ,int ,int ]:
        """Wrap, transmit, and unwrap exactly one physical APDU exchange."""
        session =getattr (self ,"session",None )
        authenticated =bool (
        session is not None and getattr (session ,"is_authenticated",False )
        )
        wire_command =command
        if session is not None and hasattr (session ,"wrap_apdu"):
            wire_command =bytes (session .wrap_apdu (list (command )))
        secure_messaging =wire_command !=command

        try :
            response_data ,sw1 ,sw2 =self .connection .transmit (
            list (wire_command )
            )
        except Exception :
            # Once a protected command may have reached the card, the host
            # cannot know whether the card advanced its MAC chain/counter.
            if authenticated and secure_messaging :
                self ._reset_session_state ()
            raise
        try :
            wire_response =bytes (response_data )
            sw1 =int (sw1 )
            sw2 =int (sw2 )
            if not 0 <=sw1 <=0xFF or not 0 <=sw2 <=0xFF :
                raise ValueError ("Card returned invalid status bytes.")
        except Exception as exc :
            if authenticated and secure_messaging :
                self ._reset_session_state ()
            raise ValueError (
            "Card returned a malformed response or invalid status bytes."
            )from exc

        requires_verification =False
        if authenticated and hasattr (session ,"response_requires_rmac"):
            requires_verification =bool (
            session .response_requires_rmac (sw1 ,sw2 )
            )
        clear_response =wire_response
        try :
            if authenticated and hasattr (session ,"unwrap_response"):
                clear_response =bytes (
                session .unwrap_response (wire_response ,sw1 ,sw2 )
                )
        except Exception as exc :
            trace .append (
            self ._trace_entry (
            sequence =sequence ,
            phase =phase ,
            command =command ,
            wire_command =wire_command ,
            wire_response =wire_response ,
            clear_response =None ,
            sw1 =sw1 ,
            sw2 =sw2 ,
            secure_messaging =secure_messaging ,
            response_verified =False if requires_verification else None ,
            policy =policy ,
            error =type (exc ).__name__ ,
            )
            )
            raise

        trace .append (
        self ._trace_entry (
        sequence =sequence ,
        phase =phase ,
        command =command ,
        wire_command =wire_command ,
        wire_response =wire_response ,
        clear_response =clear_response ,
        sw1 =sw1 ,
        sw2 =sw2 ,
        secure_messaging =secure_messaging ,
        response_verified =True if requires_verification else None ,
        policy =policy ,
        )
        )
        return clear_response ,sw1 ,sw2

    def transmit_detailed (
    self ,
    apdu_hex :str ,
    *,
    policy :Optional [ApduTransportPolicy ]=None ,
    )->ApduTransmitResult :
        """Transmit one logical APDU and return per-exchange trace metadata.

        Every ``6C`` retry and ``61``/``9F`` GET RESPONSE is treated as a new
        command and therefore passes through the active secure-channel
        wrapper and response verifier independently.
        """
        effective_policy =policy or ApduTransportPolicy ()
        trace :List [ApduExchangeTrace ]=[]
        self .last_trace =()
        self .last_error =None
        self .last_session_invalidation =None

        try :
            if self .connection is None and not self .connect ():
                raise RuntimeError ("Could not connect to a smart card reader.")
            command =bytes (HexUtils .to_bytes (apdu_hex ))
            if len (command )<4 :
                raise ValueError (
                "Command APDU must contain at least CLA, INS, P1, and P2."
                )

            session =getattr (self ,"session",None )
            authenticated_at_start =bool (
            session is not None and getattr (session ,"is_authenticated",False )
            )
            bound_channel =getattr (session ,"authenticated_channel",None )
            original_channel =(
            session .logical_channel_from_cla (command [0 ])
            if session is not None
            and hasattr (session ,"logical_channel_from_cla")
            else (4 +(command [0 ]&0x0F )if command [0 ]&0x40 else command [0 ]&0x03 )
            )
            original_ins =command [1 ]

            accumulated =bytearray ()
            current_command =command
            phase ="command"
            followups =0
            sequence =0
            while True :
                sequence +=1
                clear_data ,sw1 ,sw2 =self ._exchange_once (
                current_command ,
                phase =phase ,
                sequence =sequence ,
                policy =effective_policy ,
                trace =trace ,
                )

                if sw1 ==0x6C and effective_policy .retry_wrong_length :
                    followups +=1
                    if followups >effective_policy .max_followups :
                        raise RuntimeError (
                        "Card returned too many APDU continuation responses."
                        )
                    current_command =bytes (
                    self ._correct_apdu_le (list (current_command ),sw2 )
                    )
                    phase ="correct-le"
                    continue

                if (
                    sw1 in (0x61 ,0x9F )
                    and effective_policy .follow_response_data
                ):
                    accumulated .extend (clear_data )
                    followups +=1
                    if followups >effective_policy .max_followups :
                        raise RuntimeError (
                        "Card returned too many APDU continuation responses."
                        )
                    get_response_cla =self ._get_response_cla (
                    current_command [0 ]
                    )
                    current_command =bytes (
                    [get_response_cla ,0xC0 ,0x00 ,0x00 ,sw2 ]
                    )
                    phase ="get-response"
                    continue

                accumulated .extend (clear_data )
                invalidated =False
                invalidation_reason =None
                if authenticated_at_start and (sw1 ,sw2 )in (
                    (0x69 ,0x82 ),
                    (0x69 ,0x88 ),
                ):
                    self ._reset_session_state ()
                    invalidated =True
                    invalidation_reason =(
                    f"Card returned secure-messaging status {sw1:02X}{sw2:02X}; "
                    "the SCP session was invalidated and must be re-authenticated."
                    )
                    self .last_session_invalidation =invalidation_reason
                elif (
                    authenticated_at_start
                    and original_ins ==0xA4
                    and bound_channel is not None
                    and original_channel ==int (bound_channel )
                    and (sw1 ,sw2 )==(0x90 ,0x00 )
                ):
                    self ._reset_session_state ()
                    invalidated =True
                    invalidation_reason =(
                    "Successful SELECT on the authenticated logical channel "
                    "terminated the SCP03 session; re-authentication is required."
                    )
                    self .last_session_invalidation =invalidation_reason

                result =ApduTransmitResult (
                data =bytes (accumulated ),
                sw1 =sw1 ,
                sw2 =sw2 ,
                trace =tuple (trace ),
                session_invalidated =invalidated ,
                invalidation_reason =invalidation_reason ,
                )
                self .last_trace =result .trace
                return result
        except Exception as exc :
            if isinstance (exc ,Scp03ResponseProtectionError ):
                self ._reset_session_state ()
            message =str (exc ).strip ()or type (exc ).__name__
            if len (message )>400 :
                message =message [:397 ]+"..."
            wrapped =ApduTransportError (
            message ,
            trace =tuple (trace ),
            cause_type =type (exc ).__name__ ,
            )
            self .last_trace =wrapped .trace
            self .last_error =message
            raise wrapped from exc

    def transmit (self ,apdu_hex :str ,silent :bool =False )->Tuple [bytes ,int ,int ]:
        """Transmit a logical APDU while preserving the legacy tuple API."""
        try :
            result =self .transmit_detailed (apdu_hex )
            if not silent :
                print (
                f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} "
                f"{result.data.hex().upper()} {result.sw1:02X}{result.sw2:02X}"
                )
                if result .session_invalidated :
                    print (
                    f"{Config.Colors.CYAN}[*] "
                    f"{result.invalidation_reason}{Config.Colors.ENDC}"
                    )
            return result .as_tuple ()
        except ApduTransportError as exc :
            if not silent :
                print (
                f"{Config.Colors.FAIL}[!] Transmit Error: "
                f"{exc}{Config.Colors.ENDC}"
                )
            # Compatibility: legacy callers expect a tuple on local failure.
            # No unverified response bytes are ever returned.
            return b"",0x6F ,0x00

    @staticmethod
    def _correct_apdu_le (apdu :List [int ],correct_le :int )->List [int ]:
        """Return *apdu* with the ISO 7816 short/extended Le corrected.

        ``6C00`` means 256 bytes.  That is encoded as ``00`` in a short
        APDU but as ``0100`` in an extended APDU (``0000`` would mean
        65536).  Commands without an Le are promoted to case 2/4 while
        their data field is preserved.
        """
        command =[int (byte )&0xFF for byte in apdu ]
        if len (command )<4 :
            raise ValueError ("Cannot correct Le on an APDU shorter than four bytes.")

        short_le =int (correct_le )&0xFF
        extended_le =256 if short_le ==0 else short_le

        if len (command )==4 :
            return command +[short_le ]
        if len (command )==5 :
            command [4 ]=short_le
            return command

        first_length =command [4 ]
        if first_length !=0 :
            data_end =5 +first_length
            if len (command )<data_end :
                raise ValueError ("Cannot correct Le on a truncated short APDU.")
            if len (command )==data_end :
                return command +[short_le ]
            if len (command )==data_end +1 :
                command [-1 ]=short_le
                return command
            raise ValueError ("Cannot correct Le on a malformed short APDU.")

        if len (command )<7 :
            raise ValueError ("Cannot correct Le on a truncated extended APDU.")
        encoded_extended_le =list (extended_le .to_bytes (2 ,"big"))
        if len (command )==7 :
            command [5 :7 ]=encoded_extended_le
            return command

        extended_lc =(command [5 ]<<8 )|command [6 ]
        if extended_lc ==0 :
            raise ValueError ("Extended Lc=0 is invalid outside case 2E.")
        data_end =7 +extended_lc
        if len (command )<data_end :
            raise ValueError ("Cannot correct Le on a truncated extended APDU.")
        if len (command )==data_end :
            return command +encoded_extended_le
        if len (command )==data_end +2 :
            command [-2 :]=encoded_extended_le
            return command
        raise ValueError ("Cannot correct Le on a malformed extended APDU.")

    @staticmethod
    def _get_response_cla (command_cla :int )->int :
        """Preserve the logical channel while clearing command-specific CLA bits."""
        cla =int (command_cla )&0xFF
        if cla &0x40 :
            return 0x40 |(cla &0x0F )
        return cla &0x03

    def _transmit_recursive (self ,apdu :List [int ])->Tuple [List [int ],int ,int ]:
        command =[int (byte )&0xFF for byte in apdu ]
        data ,sw1 ,sw2 =self .connection .transmit (command )
        if sw1 ==0x6C :
            command =self ._correct_apdu_le (command ,sw2 )
            data ,sw1 ,sw2 =self .connection .transmit (command )
        if sw1 ==0x61 or sw1 ==0x9F :
            accumulated =list (data )
            get_response_cla =self ._get_response_cla (command [0 ])
            followups =0
            while sw1 ==0x61 or sw1 ==0x9F :
                followups +=1
                if followups >64 :
                    raise RuntimeError ("Card returned too many GET RESPONSE continuations.")
                get_response =[get_response_cla ,0xC0 ,0x00 ,0x00 ,sw2 ]
                chunk ,sw1 ,sw2 =self .connection .transmit (get_response )
                if sw1 ==0x6C :
                    followups +=1
                    if followups >64 :
                        raise RuntimeError ("Card returned too many GET RESPONSE continuations.")
                    get_response =self ._correct_apdu_le (get_response ,sw2 )
                    chunk ,sw1 ,sw2 =self .connection .transmit (get_response )
                accumulated .extend (chunk )
            return accumulated ,sw1 ,sw2 
        return data ,sw1 ,sw2
