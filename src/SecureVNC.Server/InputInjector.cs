using System.Runtime.InteropServices;
using SecureVNC.Shared.Protocol;
using static SecureVNC.Server.Native;

namespace SecureVNC.Server;

/// <summary>Turns RFB pointer events and SecureVNC key events into SendInput calls. One per session.</summary>
internal sealed class InputInjector
{
    private static readonly int InputSize = Marshal.SizeOf<INPUT>();
    private readonly HashSet<(ushort Vk, ushort Scan, bool Ext)> _down = [];
    private byte _mask;
    private int _lastX, _lastY;

    public void Pointer(byte mask, int x, int y)
    {
        int vw = Math.Max(2, GetSystemMetrics(SM_CXVIRTUALSCREEN));
        int vh = Math.Max(2, GetSystemMetrics(SM_CYVIRTUALSCREEN));
        int nx = (int)(Math.Clamp(x, 0, vw - 1) * 65535L / (vw - 1));
        int ny = (int)(Math.Clamp(y, 0, vh - 1) * 65535L / (vh - 1));
        _lastX = x;
        _lastY = y;

        var inputs = new List<INPUT>(4) { Mouse(nx, ny, 0, MOUSEEVENTF_MOVE) };

        void Button(byte bit, uint down, uint up)
        {
            bool was = (_mask & bit) != 0, now = (mask & bit) != 0;
            if (was != now) inputs.Add(Mouse(nx, ny, 0, now ? down : up));
        }
        Button(Rfb.ButtonLeft, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP);
        Button(Rfb.ButtonMiddle, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP);
        Button(Rfb.ButtonRight, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP);

        // Wheel "buttons": each press is one notch.
        void Wheel(byte bit, uint flag, int delta)
        {
            if ((mask & bit) != 0 && (_mask & bit) == 0) inputs.Add(Mouse(nx, ny, unchecked((uint)delta), flag));
        }
        Wheel(Rfb.WheelUp, MOUSEEVENTF_WHEEL, 120);
        Wheel(Rfb.WheelDown, MOUSEEVENTF_WHEEL, -120);
        Wheel(Rfb.WheelLeft, MOUSEEVENTF_HWHEEL, -120);
        Wheel(Rfb.WheelRight, MOUSEEVENTF_HWHEEL, 120);

        _mask = mask;
        Send(inputs);
    }

    public void Key(bool down, ushort vk, ushort scan, bool extended)
    {
        var ki = new KEYBDINPUT();
        uint flags = (extended ? KEYEVENTF_EXTENDEDKEY : 0) | (down ? 0 : KEYEVENTF_KEYUP);
        if (scan != 0)
        {
            // Scan codes make the server's keyboard layout decide the character, like RDP does.
            ki.wScan = scan;
            flags |= KEYEVENTF_SCANCODE;
        }
        else
        {
            ki.wVk = vk;
        }
        ki.dwFlags = flags;
        Send([new INPUT { type = INPUT_KEYBOARD, u = new InputUnion { ki = ki } }]);

        if (down) _down.Add((vk, scan, extended));
        else _down.Remove((vk, scan, extended));
    }

    /// <summary>Releases keys and buttons still held when the session ends, so nothing stays stuck.</summary>
    public void ReleaseAll()
    {
        foreach (var k in _down.ToList()) Key(false, k.Vk, k.Scan, k.Ext);
        if (_mask != 0) Pointer(0, _lastX, _lastY);
    }

    private static INPUT Mouse(int nx, int ny, uint data, uint flags) => new()
    {
        type = INPUT_MOUSE,
        u = new InputUnion
        {
            mi = new MOUSEINPUT
            {
                dx = nx,
                dy = ny,
                mouseData = data,
                dwFlags = flags | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            },
        },
    };

    private static void Send(List<INPUT> inputs) => SendInput((uint)inputs.Count, inputs.ToArray(), InputSize);
}
