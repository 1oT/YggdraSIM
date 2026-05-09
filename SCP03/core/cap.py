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

"""CAP (Converted Applet) file parser: reads JavaCard CAP archives and extracts load-file data blocks."""
import os
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass
class CapComponentRecord:
    name: str
    tag: int
    length: int
    blob_offset: int
    load_offset: int
    payload_offset: int
    end_offset: int


@dataclass
class CapLoadChunk:
    index: int
    start_offset: int
    end_offset: int
    payload: bytes
    component_names: List[str]
    split_component: Optional[str]


@dataclass
class CapParseResult:
    load_block: bytes
    package_aid: bytes
    applet_aids: List[bytes]
    component_blob: bytes
    load_header_length: int
    components: List[CapComponentRecord]


class CapFileParser:

    ORDER = [
        "Header.cap",
        "Directory.cap",
        "Import.cap",
        "Applet.cap",
        "Class.cap",
        "Method.cap",
        "StaticField.cap",
        "Export.cap",
        "ConstantPool.cap",
        "RefLocation.cap",
        "Descriptor.cap",
    ]
    TAG_NAMES = {
        0x01: "Header.cap",
        0x02: "Directory.cap",
        0x03: "Applet.cap",
        0x04: "Import.cap",
        0x05: "ConstantPool.cap",
        0x06: "Class.cap",
        0x07: "Method.cap",
        0x08: "StaticField.cap",
        0x09: "RefLocation.cap",
        0x0A: "Export.cap",
        0x0B: "Descriptor.cap",
        0x0C: "Debug.cap",
    }

    @staticmethod
    def parse(cap_path: str) -> Tuple[bytes, bytes, List[bytes]]:
        """
        Parses a CAP (Zip) or IJC (Raw) file.
        Returns: (LoadFileBlock, PackageAID, List[AppletAIDs])
        """
        parsed = CapFileParser.parse_with_metadata(cap_path)
        return parsed.load_block, parsed.package_aid, parsed.applet_aids

    @staticmethod
    def parse_with_metadata(cap_path: str) -> CapParseResult:
        """Parse a CAP or IJC load file and return a ``CapParseResult`` with the component map and metadata."""
        if not os.path.exists(cap_path):
            raise FileNotFoundError(f"File not found: {cap_path}")

        if cap_path.lower().endswith(".ijc"):
            return CapFileParser._parse_ijc(cap_path)
        return CapFileParser._parse_cap(cap_path)

    @staticmethod
    def _encode_ber_length(length: int) -> bytes:
        if length <= 0x7F:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82]) + length.to_bytes(2, "big")
        raise ValueError("Load file block exceeds supported BER length encoding.")

    @staticmethod
    def _decode_ber_length(data: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(data):
            raise ValueError("Invalid BER length field.")

        first = data[offset]
        offset += 1

        if first <= 0x7F:
            return first, offset

        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("Invalid BER length field.")

        length = int.from_bytes(data[offset:offset + num_bytes], "big")
        return length, offset + num_bytes

    @staticmethod
    def _wrap_load_file_block(component_blob: bytes) -> bytes:
        return bytes([0xC4]) + CapFileParser._encode_ber_length(len(component_blob)) + component_blob

    @staticmethod 
    def _unwrap_load_file_block(data: bytes) -> Tuple[bytes, int, int]:
        if len(data) > 2 and data[0] == 0xC4:
            try:
                length, payload_offset = CapFileParser._decode_ber_length(data, 1)
                end_offset = payload_offset + length
                if end_offset <= len(data):
                    return data[payload_offset:end_offset], payload_offset, end_offset
            except Exception:
                pass
        return data, 0, len(data)

    @staticmethod
    def _extract_component_blob(data: bytes) -> bytes:
        component_blob, _, _ = CapFileParser._unwrap_load_file_block(data)
        return component_blob

    @staticmethod
    def _build_parse_result(
        load_block: bytes,
        component_blob: bytes,
        pkg_aid: bytes,
        applet_aids: List[bytes],
        ordered_names: Optional[Sequence[str]] = None,
    ) -> CapParseResult:
        load_header_length = len(load_block) - len(component_blob)
        components = CapFileParser._parse_component_blob(
            component_blob,
            load_header_length,
            ordered_names,
        )
        return CapParseResult(
            load_block=load_block,
            package_aid=pkg_aid,
            applet_aids=applet_aids,
            component_blob=component_blob,
            load_header_length=load_header_length,
            components=components,
        )

    @staticmethod
    def _parse_component_blob(
        component_blob: bytes,
        load_header_length: int,
        ordered_names: Optional[Sequence[str]] = None,
    ) -> List[CapComponentRecord]:
        components: List[CapComponentRecord] = []
        offset = 0
        component_index = 0
        blob_len = len(component_blob)

        while offset < blob_len:
            if offset + 3 > blob_len:
                raise ValueError("CAP component blob ended mid-header.")

            tag = component_blob[offset]
            length = int.from_bytes(component_blob[offset + 1:offset + 3], "big")
            end_offset = offset + 3 + length
            if end_offset > blob_len:
                raise ValueError("CAP component length exceeds available data.")

            component_name = CapFileParser.TAG_NAMES.get(tag, f"Tag{tag:02X}.cap")
            if ordered_names is not None and component_index < len(ordered_names):
                component_name = ordered_names[component_index]

            load_offset = load_header_length + offset
            components.append(
                CapComponentRecord(
                    name=component_name,
                    tag=tag,
                    length=length,
                    blob_offset=offset,
                    load_offset=load_offset,
                    payload_offset=load_offset + 3,
                    end_offset=load_header_length + end_offset,
                )
            )
            offset = end_offset
            component_index += 1

        return components

    @staticmethod
    def _component_names_for_range(
        components: List[CapComponentRecord],
        start_offset: int,
        end_offset: int,
    ) -> List[str]:
        names: List[str] = []
        for component in components:
            overlaps = start_offset < component.end_offset and end_offset > component.load_offset
            if overlaps:
                names.append(component.name)
        return names

    @staticmethod
    def _find_split_component(
        components: List[CapComponentRecord],
        end_offset: int,
        total_length: int,
    ) -> Optional[str]:
        if end_offset >= total_length:
            return None
        for component in components:
            if component.load_offset < end_offset < component.end_offset:
                return component.name
        return None

    @staticmethod
    def _choose_chunk_boundary(
        start_offset: int,
        max_end_offset: int,
        preferred_boundaries: Sequence[int],
        components: List[CapComponentRecord],
    ) -> int:
        for boundary in preferred_boundaries:
            if start_offset < boundary <= max_end_offset:
                return boundary

        for component in components:
            if start_offset < component.load_offset < max_end_offset:
                if max_end_offset < component.payload_offset:
                    return component.load_offset

        return max_end_offset

    @staticmethod
    def _read_u2(data: bytes, offset: int) -> Optional[int]:
        if offset + 2 > len(data):
            return None
        return int.from_bytes(data[offset:offset + 2], "big")

    @staticmethod
    def _constant_pool_boundaries(
        component: CapComponentRecord,
        component_data: bytes,
    ) -> List[int]:
        boundaries: List[int] = []
        count = CapFileParser._read_u2(component_data, 3)
        if count is None:
            return boundaries

        entries_start = component.load_offset + 5
        entries_len = count * 4
        component_end = component.end_offset
        if entries_start + entries_len != component_end:
            return boundaries

        for index in range(1, count):
            boundaries.append(entries_start + (index * 4))
        return boundaries

    @staticmethod
    def _ref_location_boundaries(
        component: CapComponentRecord,
        component_data: bytes,
    ) -> List[int]:
        boundaries: List[int] = []
        byte_index_count = CapFileParser._read_u2(component_data, 3)
        if byte_index_count is None:
            return boundaries

        first_array_end = 5 + byte_index_count
        if first_array_end > len(component_data):
            return boundaries

        byte2_index_count = CapFileParser._read_u2(component_data, first_array_end)
        if byte2_index_count is None:
            return boundaries

        second_array_end = first_array_end + 2 + byte2_index_count
        if second_array_end != len(component_data):
            return boundaries

        boundaries.append(component.load_offset + first_array_end)
        boundaries.append(component.load_offset + first_array_end + 2)
        return boundaries

    @staticmethod
    def _component_internal_boundaries(
        parsed: CapParseResult,
        component: CapComponentRecord,
    ) -> List[int]:
        component_data = parsed.component_blob[component.blob_offset:component.blob_offset + 3 + component.length]
        if len(component_data) != 3 + component.length:
            return []

        if component.tag == 0x05:
            return CapFileParser._constant_pool_boundaries(component, component_data)
        if component.tag == 0x09:
            return CapFileParser._ref_location_boundaries(component, component_data)
        return []

    @staticmethod
    def plan_load_chunks(parsed: CapParseResult, max_chunk_size: int) -> List[CapLoadChunk]:
        """Segment a parsed CAP load block into ``CapLoadChunk`` objects sized for the target card's *max_chunk_size*."""
        if max_chunk_size <= 0:
            raise ValueError("Chunk size must be greater than zero.")

        load_data = parsed.load_block
        total_length = len(load_data)
        if total_length == 0:
            return []

        components = parsed.components
        preferred_boundary_set = {
            component.end_offset
            for component in components
            if component.end_offset < total_length
        }
        for component in components:
            if component.end_offset - component.load_offset > max_chunk_size:
                preferred_boundary_set.update(
                    boundary
                    for boundary in CapFileParser._component_internal_boundaries(parsed, component)
                    if component.load_offset < boundary < component.end_offset
                )

        preferred_boundaries = sorted(preferred_boundary_set, reverse=True)

        chunks: List[CapLoadChunk] = []
        start_offset = 0

        while start_offset < total_length:
            max_end_offset = min(start_offset + max_chunk_size, total_length)
            if max_end_offset >= total_length:
                end_offset = total_length
            else:
                end_offset = CapFileParser._choose_chunk_boundary(
                    start_offset,
                    max_end_offset,
                    preferred_boundaries,
                    components,
                )

            if end_offset <= start_offset:
                raise ValueError("CAP chunk planner produced an empty chunk.")

            payload = load_data[start_offset:end_offset]
            chunks.append(
                CapLoadChunk(
                    index=len(chunks),
                    start_offset=start_offset,
                    end_offset=end_offset,
                    payload=payload,
                    component_names=CapFileParser._component_names_for_range(
                        components,
                        start_offset,
                        end_offset,
                    ),
                    split_component=CapFileParser._find_split_component(
                        components,
                        end_offset,
                        total_length,
                    ),
                )
            )
            start_offset = end_offset

        return chunks

    @staticmethod
    def _parse_ijc(ijc_path: str) -> CapParseResult:
        """
        Parses a pre-arranged .ijc file directly.
        Iterates over the component tags to extract metadata.
        """
        with open(ijc_path, "rb") as file_obj:
            raw_data = file_obj.read()

        component_blob, _, load_end_offset = CapFileParser._unwrap_load_file_block(raw_data)
        load_block = raw_data[:load_end_offset]
        pkg_aid = b""
        applet_aids: List[bytes] = []
        offset = 0
        data_len = len(component_blob)

        while offset < data_len:
            if offset + 3 > data_len:
                raise ValueError("CAP component blob ended mid-header.")

            tag = component_blob[offset]
            size = int.from_bytes(component_blob[offset + 1:offset + 3], byteorder="big")
            comp_end = offset + 3 + size
            if comp_end > data_len:
                raise ValueError("CAP component length exceeds available data.")

            comp_data = component_blob[offset:comp_end]
            if tag == 1:
                pkg_aid = CapFileParser._extract_pkg_aid(comp_data)
            elif tag == 3:
                applet_aids = CapFileParser._extract_applet_aids(comp_data)

            offset = comp_end

        return CapFileParser._build_parse_result(
            load_block=load_block,
            component_blob=component_blob,
            pkg_aid=pkg_aid,
            applet_aids=applet_aids,
        )

    @staticmethod
    def _parse_cap(cap_path: str) -> CapParseResult:
        """
        Parses a standard .cap ZIP archive file.
        Extracts, orders, and concatenates the internal .cap components.
        """
        blob = bytearray()
        pkg_aid = b""
        applet_aids: List[bytes] = []
        ordered_names: List[str] = []

        try:
            with zipfile.ZipFile(cap_path, "r") as cap_zip:
                all_files = cap_zip.namelist()
                component_map: Dict[str, str] = {}
                for file_name in all_files:
                    if file_name.lower().endswith(".cap"):
                        base_name = os.path.basename(file_name)
                        component_map[base_name] = file_name

                for component_name in CapFileParser.ORDER:
                    if component_name in component_map:
                        path = component_map[component_name]
                        data = cap_zip.read(path)
                        blob.extend(data)
                        ordered_names.append(component_name)

                        if component_name == "Header.cap":
                            pkg_aid = CapFileParser._extract_pkg_aid(data)
                        elif component_name == "Applet.cap":
                            applet_aids = CapFileParser._extract_applet_aids(data)
        except zipfile.BadZipFile as exc:
            raise ValueError("Invalid CAP file format (Not a valid ZIP)") from exc

        if len(blob) == 0:
            raise ValueError("CAP file did not contain any recognized load components.")

        component_blob = bytes(blob)
        load_block = CapFileParser._wrap_load_file_block(component_blob)
        return CapFileParser._build_parse_result(
            load_block=load_block,
            component_blob=component_blob,
            pkg_aid=pkg_aid,
            applet_aids=applet_aids,
            ordered_names=ordered_names,
        )

    @staticmethod
    def _extract_pkg_aid(data: bytes) -> bytes:
        try:
            if len(data) > 13:
                aid_len = data[12]
                return data[13:13 + aid_len]
        except Exception:
            pass
        return b""

    @staticmethod
    def _extract_applet_aids(data: bytes) -> List[bytes]:
        aids: List[bytes] = []
        try:
            if len(data) >= 4:
                count = data[3]
                offset = 4
                for _ in range(count):
                    if offset >= len(data):
                        break

                    aid_len = data[offset]
                    offset += 1
                    aid = data[offset:offset + aid_len]
                    aids.append(aid)
                    offset += aid_len + 2
        except Exception:
            pass

        return aids