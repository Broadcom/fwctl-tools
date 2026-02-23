#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
Safer BNXT fwctl client that tries to avoid completion queue issues
"""

import os
import sys
import struct
import fcntl
import ctypes
import logging
from typing import Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# fwctl constants
FWCTL_TYPE = 0x9A
FWCTL_CMD_INFO = 0
FWCTL_CMD_RPC = 1

# RPC scopes
FWCTL_RPC_DEBUG_READ_ONLY = 1

# HWRM request types
HWRM_VER_GET = 0x0

class FwctlClient:
    """Client for communicating with BNXT fwctl devices"""
    
    def __init__(self, device_path: str = "/dev/fwctl/fwctl0"):
        self.device_path = device_path
        self.fd = None
        self.device_type = None
        self.device_info = None
    
    def open(self) -> bool:
        """Open the fwctl device"""
        try:
            self.fd = os.open(self.device_path, os.O_RDWR)
            logger.info(f"Opened device: {self.device_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to open device: {e}")
            return False
    
    def close(self):
        """Close the fwctl device"""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
    
    def get_device_info(self) -> Optional[dict]:
        """Get device information using FWCTL_INFO"""
        if self.fd is None:
            logger.error("Device not opened")
            return None
        
        try:
            # Create buffer for device data
            buffer_size = 1024
            device_data_array = (ctypes.c_uint8 * buffer_size)()
            buffer_address = ctypes.addressof(device_data_array)
            
            # Prepare info structure
            info_struct = bytearray(struct.pack('<IIIIQ',
                                                24,  # size
                                                0,   # flags
                                                0,   # device_type (output)
                                                buffer_size,  # device_data_len
                                                buffer_address))  # device_data pointer
            
            # Perform ioctl
            result = fcntl.ioctl(self.fd, FWCTL_TYPE << 8 | FWCTL_CMD_INFO, info_struct)
            
            # Parse response
            size, flags, device_type, device_data_len, device_data_ptr = struct.unpack('<IIIIQ', info_struct)
            
            # Extract device data
            device_data = None
            if device_data_len > 0:
                device_data = bytes(device_data_array[:device_data_len])
            
            self.device_type = device_type
            self.device_info = {
                'size': size,
                'flags': flags,
                'device_type': device_type,
                'data_len': device_data_len,
                'data': device_data
            }
            
            logger.info(f"Device type: {device_type}, Data len: {device_data_len}")
            if device_data:
                logger.debug(f"Device data: {device_data.hex()}")
            
            return self.device_info
            
        except Exception as e:
            logger.error(f"Failed to get device info: {e}")
            return None
    
    def parse_hwrm_ver_get_output(self, response_data: bytes):
        """Parse the hwrm_ver_get_output structure"""
        try:
            logger.info(f"Parsing response data of length: {len(response_data)} bytes")
            
            # Parse step by step to avoid struct format issues
            offset = 0
            
            # HWRM header (8 bytes)
            error_code, req_type, seq_id, resp_len = struct.unpack_from('<HHHH', response_data, offset)
            offset += 8
            logger.info(f"HWRM Header - error_code: {error_code}, req_type: {req_type}, seq_id: {seq_id}, resp_len: {resp_len}")
            
            # HWRM interface version (4 bytes)
            hwrm_intf_maj, hwrm_intf_min, hwrm_intf_upd, hwrm_intf_rsvd = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # HWRM firmware version (4 bytes)
            hwrm_fw_maj, hwrm_fw_min, hwrm_fw_bld, hwrm_fw_rsvd = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # Management firmware version (4 bytes)
            mgmt_fw_maj, mgmt_fw_min, mgmt_fw_bld, mgmt_fw_rsvd = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # NetCtrl firmware version (4 bytes)
            netctrl_fw_maj, netctrl_fw_min, netctrl_fw_bld, netctrl_fw_rsvd = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # Device capabilities config (4 bytes)
            dev_caps_cfg = struct.unpack_from('<I', response_data, offset)[0]
            offset += 4
            
            # RoCE firmware version (4 bytes)
            roce_fw_maj, roce_fw_min, roce_fw_bld, roce_fw_rsvd = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # Firmware names (5 * 16 bytes = 80 bytes)
            hwrm_fw_name = struct.unpack_from('<16s', response_data, offset)[0].decode('ascii', errors='ignore').rstrip('\x00')
            offset += 16
            mgmt_fw_name = struct.unpack_from('<16s', response_data, offset)[0].decode('ascii', errors='ignore').rstrip('\x00')
            offset += 16
            netctrl_fw_name = struct.unpack_from('<16s', response_data, offset)[0].decode('ascii', errors='ignore').rstrip('\x00')
            offset += 16
            active_pkg_name = struct.unpack_from('<16s', response_data, offset)[0].decode('ascii', errors='ignore').rstrip('\x00')
            offset += 16
            roce_fw_name = struct.unpack_from('<16s', response_data, offset)[0].decode('ascii', errors='ignore').rstrip('\x00')
            offset += 16
            
            # Chip information (6 bytes)
            chip_num = struct.unpack_from('<H', response_data, offset)[0]
            offset += 2
            chip_rev, chip_metal, chip_bond_id, chip_platform_type = struct.unpack_from('<BBBB', response_data, offset)
            offset += 4
            
            # Limits (4 bytes)
            max_req_win_len, max_resp_len = struct.unpack_from('<HH', response_data, offset)
            offset += 4
            
            # Print HWRM firmware versions in decimal
            logger.info("=== HWRM Firmware Versions ===")
            logger.info(f"HWRM Interface: {hwrm_intf_maj}.{hwrm_intf_min}.{hwrm_intf_upd}")
            logger.info(f"HWRM Firmware: {hwrm_fw_maj}.{hwrm_fw_min}.{hwrm_fw_bld}")
            logger.info(f"Management Firmware: {mgmt_fw_maj}.{mgmt_fw_min}.{mgmt_fw_bld}")
            logger.info(f"NetCtrl Firmware: {netctrl_fw_maj}.{netctrl_fw_min}.{netctrl_fw_bld}")
            logger.info(f"RoCE Firmware: {roce_fw_maj}.{roce_fw_min}.{roce_fw_bld}")
            
            # Print firmware names
            logger.info("=== Firmware Names ===")
            logger.info(f"HWRM FW Name: {hwrm_fw_name}")
            logger.info(f"Management FW Name: {mgmt_fw_name}")
            logger.info(f"NetCtrl FW Name: {netctrl_fw_name}")
            logger.info(f"Active Package Name: {active_pkg_name}")
            logger.info(f"RoCE FW Name: {roce_fw_name}")
            
            # Print chip information
            logger.info("=== Chip Information ===")
            logger.info(f"Chip Number: {chip_num}")
            logger.info(f"Chip Revision: {chip_rev}")
            logger.info(f"Chip Metal: {chip_metal}")
            logger.info(f"Chip Bond ID: {chip_bond_id}")
            
            # Print platform type
            platform_types = {
                0x0: "ASIC",
                0x1: "FPGA", 
                0x2: "PALLADIUM"
            }
            platform_name = platform_types.get(chip_platform_type, f"Unknown ({chip_platform_type})")
            logger.info(f"Chip Platform Type: {platform_name}")
            
            # Print device capabilities
            logger.info("=== Device Capabilities ===")
            logger.info(f"Device Caps Config: 0x{dev_caps_cfg:x}")
            
            # Print limits
            logger.info("=== Limits ===")
            logger.info(f"Max Request Window Length: {max_req_win_len}")
            logger.info(f"Max Response Length: {max_resp_len}")
            
            logger.info(f"Total parsed: {offset} bytes")
            
        except Exception as e:
            logger.error(f"Failed to parse HWRM_VER_GET output: {e}")
            logger.error(f"Response data length: {len(response_data)}")
            logger.error(f"Response data: {response_data.hex()}")
    
    def send_hwrm_ver_get(self) -> bool:
        """Send HWRM_VER_GET command with safer parameters"""
        logger.info("Sending HWRM_VER_GET command...")
        
        try:
            # Step 1: Create HWRM_VER_GET input structure with safer parameters
            # Try to avoid completion queue issues by using different parameters
            hwrm_input = struct.pack('<HHHHQBBBBBBBB',
                                    HWRM_VER_GET,  # req_type
                                    0xFFFF,        # cmpl_ring (use invalid ring to avoid completion issues)
                                    1,             # seq_id
                                    0,             # target_id
                                    0,             # resp_addr
                                    0,             # hwrm_intf_maj
                                    0,             # hwrm_intf_min
                                    0,             # hwrm_intf_upd
                                    0, 0, 0, 0, 0) # unused_0[5]
            
            logger.debug(f"HWRM input: {hwrm_input.hex()}")
            
            # Step 2: Create fwctl_rpc_bnxt structure
            # struct fwctl_rpc_bnxt {
            #     __aligned_u64 req;      # Pointer to HWRM input
            #     __u32 req_len;          # Length of HWRM input
            #     __u32 timeout;          # Timeout (0 = default)
            #     __u32 reserved[2];      # Reserved, must be 0
            #     __aligned_u64 reserved1;# Reserved, must be 0
            # }
            
            # Allocate memory for HWRM input
            input_size = len(hwrm_input)
            input_buffer = bytearray(hwrm_input)
            input_address = ctypes.addressof(ctypes.c_uint8.from_buffer(input_buffer))
            
            # Pack the fwctl_rpc_bnxt structure
            bnxt_rpc = struct.pack('<QIIIIQ',
                                  input_address,  # req
                                  input_size,     # req_len
                                  0,              # timeout (use default)
                                  0,              # reserved[0]
                                  0,              # reserved[1]
                                  0)              # reserved1
            
            logger.debug(f"BNXT RPC struct: {bnxt_rpc.hex()}")
            
            # Step 3: Create fwctl_rpc structure
            # struct fwctl_rpc {
            #     __u32 size;             # Size of this structure
            #     enum fwctl_rpc_scope scope;  # RPC scope
            #     __u32 in_len;           # Length of input data
            #     __u32 out_len;          # Length of output buffer
            #     __aligned_u64 in;       # Pointer to input data
            #     __aligned_u64 out;     # Pointer to output buffer
            # }
            
            # Allocate memory for BNXT RPC structure
            bnxt_rpc_size = len(bnxt_rpc)
            bnxt_rpc_buffer = bytearray(bnxt_rpc)
            bnxt_rpc_address = ctypes.addressof(ctypes.c_uint8.from_buffer(bnxt_rpc_buffer))
            
            # Allocate output buffer
            output_size = 1024
            output_buffer = bytearray(output_size)
            output_address = ctypes.addressof(ctypes.c_uint8.from_buffer(output_buffer))
            
            # Pack the fwctl_rpc structure
            rpc_struct = struct.pack('<IIIIQQ',
                                   32,  # size
                                   FWCTL_RPC_DEBUG_READ_ONLY,  # scope
                                   bnxt_rpc_size,  # in_len
                                   output_size,    # out_len
                                   bnxt_rpc_address,  # in
                                   output_address)    # out
            
            logger.debug(f"Generic RPC struct: {rpc_struct.hex()}")
            logger.debug(f"BNXT RPC address: 0x{bnxt_rpc_address:x}, Output address: 0x{output_address:x}")
            
            # Step 4: Perform ioctl
            result = fcntl.ioctl(self.fd, FWCTL_TYPE << 8 | FWCTL_CMD_RPC, rpc_struct)
            # logger.info(f"ioctl result: {result}")
            
            # Step 5: Parse response
            size, scope, in_len, out_len, in_ptr, out_ptr = struct.unpack('<IIIIQQ', rpc_struct)
            
            logger.info(f"RPC response - in_len: {in_len}, out_len: {out_len}")
            
            if out_len > 0:
                response_data = bytes(output_buffer[:out_len])
                # logger.info(f"Response data: {response_data.hex()}")
                
                # Parse HWRM_VER_GET output
                if out_len >= 24:  # Minimum HWRM header size
                    error_code, req_type, seq_id, resp_len = struct.unpack('<HHHH', response_data[:8])
                    logger.info(f"HWRM response - error_code: {error_code}, req_type: {req_type}, seq_id: {seq_id}, resp_len: {resp_len}")
                    
                    if error_code == 0:
                        logger.info("HWRM_VER_GET succeeded!")
                        
                        # Parse the complete hwrm_ver_get_output structure
                        self.parse_hwrm_ver_get_output(response_data)
                        return True
                    else:
                        logger.warning(f"HWRM_VER_GET failed with error code: {error_code}")
                        return False
                else:
                    logger.warning("Response too short")
                    return False
            else:
                logger.warning("No response data")
                return False
                
        except Exception as e:
            logger.error(f"HWRM_VER_GET failed: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        if self.open():
            return self
        else:
            raise RuntimeError("Failed to open device")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

def test_fwctl_client():
    """Test the fwctl client with safer parameters"""
    # logger.info("Testing BNXT fwctl client with safer HWRM_VER_GET parameters...")
    
    try:
        with FwctlClient() as client:
            # Get device info first
            info = client.get_device_info()
            if info:
                # logger.info(f"Device info: {info}")
                
                # Test HWRM_VER_GET
                success = client.send_hwrm_ver_get()
                if success:
                    logger.info("HWRM_VER_GET succeeded!")
                else:
                    logger.warning("HWRM_VER_GET failed")
            else:
                logger.error("Failed to get device info")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_fwctl_client()
    sys.exit(0 if success else 1)
