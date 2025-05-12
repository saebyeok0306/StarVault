import random

import psutil
import ctypes
from ctypes import wintypes
import struct

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# SIZE_T 정의 (64비트 시스템에서는 c_ulonglong, 32비트 시스템에서는 c_ulong)
if ctypes.sizeof(ctypes.c_void_p) == 8:
    SIZE_T = ctypes.c_ulonglong
else:
    SIZE_T = ctypes.c_ulong

# 시스템 정보 구조체
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", wintypes.LPVOID),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD)
    ]

# 메모리 기본 정보 구조체
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", SIZE_T),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def list_processes(_name):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid, name = proc.info['pid'], proc.info['name']
            # print(f"PID: {proc.info['pid']:6} | Name: {proc.info['name']}")
            if _name in name:
                print(f"PID: {proc.info['pid']:6} | Name: {proc.info['name']}")
                return {"pid": pid, "name": name, "result": True}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"pid": None, "name": None, "result": False}


def scan_process_memory(pid, target_value):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    print(f"scan_process_memory pid: {pid}, target_value: {target_value}")

    # 프로세스 핸들 열기
    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        error = ctypes.get_last_error()
        print(f"프로세스를 열 수 없습니다. 오류 코드: {error}")
        return []

    # 시스템 정보 가져오기
    system_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(system_info))

    # 메모리 주소 범위 설정
    min_address = system_info.lpMinimumApplicationAddress
    max_address = system_info.lpMaximumApplicationAddress

    # 결과 저장 리스트
    found_addresses = []

    # 대상 값 바이너리 변환
    # 32비트 정수로 가정
    try:
        target_bytes = struct.pack("i", target_value)
    except struct.error:
        # 64비트 정수일 수 있음
        target_bytes = struct.pack("q", target_value)

    print(f"검색 중: {target_value} (바이트: {target_bytes.hex()})")
    print(f"메모리 범위: {min_address} - {max_address}")

    # 메모리 스캔 시작
    current_address = min_address
    mbi = MEMORY_BASIC_INFORMATION()

    while current_address < max_address:
        # 현재 메모리 영역의 정보 가져오기
        if kernel32.VirtualQueryEx(
                process,
                ctypes.c_void_p(current_address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
        ) != ctypes.sizeof(mbi):
            break

        # 읽을 수 있는 메모리인지 확인
        if (mbi.State == MEM_COMMIT and
                mbi.Protect != 0 and
                mbi.Protect & PAGE_READWRITE):

            try:
                # 메모리 영역 크기
                region_size = mbi.RegionSize

                # 버퍼 생성
                buffer = ctypes.create_string_buffer(region_size)
                bytes_read = SIZE_T()

                # 메모리 읽기 시도
                if kernel32.ReadProcessMemory(
                        process,
                        ctypes.c_void_p(mbi.BaseAddress),
                        buffer,
                        region_size,
                        ctypes.byref(bytes_read)
                ):
                    # 데이터에서 대상 값 검색
                    data = buffer.raw[:bytes_read.value]
                    offset = 0

                    while True:
                        offset = data.find(target_bytes, offset)
                        if offset == -1:
                            break

                        found_address = mbi.BaseAddress + offset
                        found_addresses.append(found_address)
                        print(f"찾음: 주소 0x{found_address:X}")

                        offset += len(target_bytes)

            except Exception as e:
                print(f"메모리 읽기 중 오류 발생: {e}")

        # 다음 메모리 영역으로 이동
        current_address = mbi.BaseAddress + mbi.RegionSize

    kernel32.CloseHandle(process)
    return found_addresses


def read_process_memory(pid, base_address, data_type="int", size=4):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # 프로세스 핸들 열기
    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        error = ctypes.get_last_error()
        raise ctypes.WinError(error)

    try:
        # 데이터 타입에 따라 읽을 크기 설정
        if data_type == "int":
            size = 4  # 32비트 정수
            buffer = ctypes.create_string_buffer(size)
        elif data_type in ["string", "bytes"]:
            # 지정된 크기만큼 읽음
            buffer = ctypes.create_string_buffer(size)
        else:
            raise ValueError(f"지원되지 않는 데이터 타입: {data_type}")

        # 메모리 읽기
        bytes_read = SIZE_T()
        result = kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(base_address),
            buffer,
            size,
            ctypes.byref(bytes_read)
        )

        if not result:
            error = ctypes.get_last_error()
            raise ctypes.WinError(error)

        # 데이터 타입에 따라 변환
        if data_type == "int":
            return struct.unpack("i", buffer.raw)[0]
        elif data_type == "string":
            # NULL 종료 문자까지만 문자열로 변환
            null_pos = buffer.raw.find(b'\0')
            if null_pos != -1:
                return buffer.raw[:null_pos].decode('utf-8', errors='replace')
            return buffer.raw.decode('utf-8', errors='replace')
        elif data_type == "bytes":
            return buffer.raw

    finally:
        # 프로세스 핸들 닫기
        kernel32.CloseHandle(process)

def write_process_memory(pid, base_address, value, data_type="int"):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # 프로세스 핸들 열기
    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        error = ctypes.get_last_error()
        raise ctypes.WinError(error)

    try:
        # 데이터 타입에 따라 바이트로 변환
        if data_type == "int":
            buffer = struct.pack("i", value)
            size = 4
        elif data_type == "string":
            # 문자열을 NULL 종료 문자열로 변환
            if isinstance(value, str):
                buffer = value.encode('utf-8') + b'\0'
            else:
                buffer = value + b'\0'
            size = len(buffer)
        elif data_type == "bytes":
            if isinstance(value, str):
                buffer = value.encode('utf-8')
            else:
                buffer = value
            size = len(buffer)
        else:
            raise ValueError(f"지원되지 않는 데이터 타입: {data_type}")

        # 메모리 쓰기
        bytes_written = SIZE_T()
        result = kernel32.WriteProcessMemory(
            process,
            ctypes.c_void_p(base_address),
            buffer,
            size,
            ctypes.byref(bytes_written)
        )

        if not result:
            error = ctypes.get_last_error()
            raise ctypes.WinError(error)

        return bytes_written.value == size

    finally:
        # 프로세스 핸들 닫기
        kernel32.CloseHandle(process)


def get_pvariable_address(base_address, idx):
    base_address += 4*86
    base_address += 4*18*idx
    print(f"pvariable base_address: {base_address}")
    return base_address


def n2byte(value):
    return value*4


def find_process_addr(pid):
    res1 = scan_process_memory(pid, 376042173)
    res2 = scan_process_memory(pid, 1763692436)
    res3 = scan_process_memory(pid, 1551016026)

    first_addr = []
    for addr1 in res1:
        for addr2 in res2:
            if addr2 - addr1 == 4:
                first_addr.append(addr1)

    find_addr = None
    for addr1 in first_addr:
        for addr3 in res3:
            if addr3 - addr1 == 8:
                find_addr = addr1

    print(f"find_addr: {find_addr}")
    return find_addr


def main():
    target_name = "StarCraft"

    result = list_processes(target_name)
    if result['pid'] is None:
        print("프로세스를 찾을 수 없습니다.")
        return
    
    pid = result['pid']
    name = result['name']

    target_addr = find_process_addr(pid)
    if target_addr is None:
        print("주소를 찾을 수 없습니다.")
        return

    res = read_process_memory(pid, target_addr + n2byte(4), "int")
    print(f"find by value : {res}")

    rand_value = random.randint(0, 16777215)
    write_process_memory(pid, target_addr + n2byte(3), rand_value)
    print(f"write random value : {rand_value}")


if __name__ == "__main__":
    # Run the executable
    main()
