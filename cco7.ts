"use strict";

interface EventTarget {
    attachEvent?(eventNameWithOn: string, callback: EventListener): boolean;
}

module CCO7 {
    let onEvent: (source: EventTarget, eventName: string, listener: EventListener) => void;
    let onLoaded: (listener: EventListener) => void;
    
    export function initialize(): void {
        initEventHandling();
        onLoaded(isLoaded);
    }

    function initEventHandling(): void {
        if (window.addEventListener || window.attachEvent) {
            if (window.addEventListener) {
                onEvent = function (obj: EventTarget, evt: string, func: EventListener): void {
                    obj.addEventListener(evt, func);
                };
            } else {
                onEvent = function (obj: EventTarget, evt: string, func: EventListener): void {
                    if (obj.attachEvent) {
                        obj.attachEvent('on' + evt, func);
                    }
                };
            }
            onLoaded = function (func: EventListener): void {
                onEvent(document, 'DOMContentLoaded', func);
            };
        } else {
            // the dirty solution
            onEvent = function (obj: EventTarget, evt: string, func: EventListener): void {
                let cur: () => void | null | undefined = obj[evt];
                (function (objCap: EventTarget, evtCap: string, funcCap: EventListener, curCap: () => void | null | undefined) {
                    objCap[evtCap] = function (): void { funcCap(new Event(evtCap)); if (curCap) { curCap(); } };
                })(obj, 'on' + evt, func, cur);
            };
            onLoaded = function (func: EventListener) {
                onEvent(window, 'load', func);
            };
        }
    }

    function isLoaded(): void {
        let t72pButton = <HTMLInputElement | null>document.getElementById('button-t72p');
        let p2t7Button = <HTMLInputElement | null>document.getElementById('button-p2t7');

        if (t72pButton) {
            onEvent(t72pButton, 'click', t72pClicked);
        }
        if (p2t7Button) {
            onEvent(p2t7Button, 'click', p2t7Clicked);
        }

        // get a random value for the seed
        let seed: number = Math.floor(Math.random() * type7Key.length);
        let seedInput = <HTMLInputElement|null>document.getElementById('input-seed');
        if (seedInput) {
            seedInput.value = `${seed}`;
        }
    }

    function t72pClicked(): void {
        let plainElem = <HTMLInputElement>document.getElementById('input-plain');

        let t7: string = (<HTMLInputElement>document.getElementById('input-type7')).value;

        let plain: string;
        try {
            plain = type7ToPlain(t7);
        } catch (e) {
            plainElem.value = `Error: ${(<Error>e).message}`;
            return;
        }

        plainElem.value = plain;
    }

    function p2t7Clicked(): void {
        let t7Elem = <HTMLInputElement>document.getElementById('input-type7');
        let plain: string = (<HTMLInputElement>document.getElementById('input-plain')).value;
        let seed: number = +(<HTMLInputElement>document.getElementById('input-seed')).value;

        let t7: string;
        try {
            t7 = plainToType7(plain, seed);
        } catch (e) {
            t7Elem.value = `Error: ${(<Error>e).message}`;
            return;
        }
        t7Elem.value = t7;
    }

    // Cisco type-7 passwords consist of:
    // two base-10 digits encoding the offset into the key
    // followed by
    // an even number of uppercase base-16 digits hex-encoding the encoded bytes of the password
    const type7Key: string = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87";
    const type7Regex: RegExp = /^([0-9]{2})((?:[0-9A-F]{2})*)$/;

    function type7ToPlain(type7: string): string {
        let i: number;
        let matches: string[]|null = type7.match(type7Regex);
        if (matches === null) {
            if ((type7.length % 2) != 0) {
                throw new Error(`length of type-7 password (${type7.length}) not divisible by 2`);
            }
            if (type7.length < 2) {
                throw new Error(`type-7 password must be at least 2 characters long (is ${type7.length})`);
            }

            for (i = 0; i < 2; ++i) {
                if (type7[i] < '0' || type7[i] > '9') {
                    throw new Error(`type-7 salt digit at index ${i} (${type7[i]}) is not a valid base-10 digit`);
                }
            }
            for (i = 2; i < type7.length; ++i) {
                if ((type7[i] < '0' || type7[i] > '9') && (type7[i] < 'A' || type7[i] > 'F')) {
                    throw new Error(`type-7 hash digit at index ${i} (${type7[i]}) is not a valid uppercase base-16 digit`);
                }
            }

            throw new Error(`type-7 regexp matching failed for an unknown reason; this is a bug`);
        }

        let initialKeyOffset: number = parseInt(matches[1], 10);
        let hash: string = matches[2];
        let data: string = "";
        for (i = 0; i < hash.length; i += 2) {
            let byteHex: string = hash.substring(i, i+2);
            data += String.fromCharCode(parseInt(byteHex, 16));
        }

        // run the cipher
        let plainUtf8: string = type7Cipher(data, initialKeyOffset);
        let plainData: string = toUtf16(fromUtf8(plainUtf8));

        return plainData;
    }

    function plainToType7(plain: string, initialKeyOffset: number): string {
        // output seed as two decimal digits
        let ret: string = ('0' + initialKeyOffset.toString(10)).slice(-2);

        // encode password
        let plainUtf8: string = toUtf8(fromUtf16(plain));
        let encoded: string = type7Cipher(plainUtf8, initialKeyOffset);
        for (let i: number = 0; i < encoded.length; ++i) {
            ret += byteToHex(encoded.charCodeAt(i));
        }

        return ret;
    }

    function type7Cipher(data: string, initialKeyOffset: number): string {
        let ret: string = "";
        for (let i: number = 0; i < data.length; ++i) {
            let oldCC: number = data.charCodeAt(i);
            let keyCC: number = type7Key.charCodeAt((initialKeyOffset + i) % type7Key.length);
            let newCC: number = oldCC ^ keyCC;
            ret += String.fromCharCode(newCC);
        }
        return ret;
    }

    function byteToHex(num: number): string {
        if (num < 0 || num > 0xFF) {
            throw new Error(`invalid byte value ${num}`);
        }
        return ('0' + num.toString(16).toUpperCase()).slice(-2);
    }

    function fromUtf16(str: string): number[] {
        let ret: number[] = [];
        let leadingPart: number|null = null;

        for (let i: number = 0; i < str.length; ++i) {
            let char: number = str.charCodeAt(i);
            if (char >= 0xD800 && char <= 0xDBFF) {
                // leading surrogate
                if (leadingPart !== null) {
                    // following a leading surrogate?!
                    throw new Error(`position ${i}: leading surrogate 0x${char.toString(16)} following leading surrogate`);
                }

                // store for later
                leadingPart = ((char - 0xD800) << 10);
            } else if (char >= 0xDC00 && char <= 0xDFFF) {
                // trailing surrogate
                if (leadingPart === null) {
                    // not following a leading surrogate?!
                    throw new Error(`position ${i}: trailing surrogate 0x${char.toString(16)} following something that is not a leading surrogate`);
                }

                // combine the character
                let supplPoint: number =
                    leadingPart
                    + (char - 0xDC00)
                    + 0x10000
                ;
                ret.push(supplPoint);

                leadingPart = null;
            } else {
                if (leadingPart !== null) {
                    throw new Error(`position ${i}: something that is not a trailing surrogate 0x${char.toString(16)} following leading surrogate`);
                }

                // just the raw value
                ret.push(char);
            }
        }
        if (leadingPart !== null) {
            throw new Error(`leading surrogate at the end of the string`);
        }
        return ret;
    }

    function toUtf16(codePoints: number[]): string {
        let ret: string = "";

        for (let i = 0; i < codePoints.length; ++i) {
            let char: number = codePoints[i];
            if (char < 0x0000 || char >= 0x10FFFF) {
                throw new Error(`position ${i}: invalid code point 0x${char.toString(16)}`);
            }

            if (char >= 0xD800 && char <= 0xDBFF) {
                throw new Error(`position ${i}: leading surrogate`);
            } else if (char >= 0xDC00 && char <= 0xDFFF) {
                throw new Error(`position ${i}: trailing surrogate`);
            }

            if (char >= 0x10000) {
                let restChar: number = char - 0x10000;
                let leadSurr: number = 0xD800 + ((restChar >>> 10) & 0x03FF);
                let trailSurr: number = 0xDC00 + ((restChar >>> 0) & 0x03FF);

                ret += String.fromCharCode(leadSurr, trailSurr);
            } else {
                ret += String.fromCharCode(char);
            }
        }

        return ret;
    }

    function fromUtf8(str: string): number[] {
        let ret: number[] = [];
        let initialContExpected: number = 0;
        let contExpected: number = 0;
        let assembly: number|null = null;

        for (let i = 0; i < str.length; ++i) {
            let char: number = str.charCodeAt(i);

            if ((char & 0b11000000) === 0b11000000) {
                // start of a multibyte sequence
                if (assembly !== null) {
                    throw new Error(`position ${i}: start of a new multibyte sequence 0x${char.toString(16)} while ${contExpected} bytes from a ${initialContExpected}-byte sequence are outstanding`);
                }

                if ((char & 0b11111000) === 0b11110000) {
                    initialContExpected = contExpected = 3;
                    assembly = char & 0b00000111;
                } else if ((char & 0b11110000) == 0b11100000) {
                    initialContExpected = contExpected = 2;
                    assembly = char & 0b00001111;
                } else if ((char & 0b11100000) == 0b11000000) {
                    initialContExpected = contExpected = 1;
                    assembly = char & 0b00011111;
                } else {
                    throw new Error(`position ${i}: invalid start of multibyte sequence 0x${char.toString(16)}`);
                }
            } else if ((char & 0b11000000) === 0b10000000) {
                // continuation
                if (assembly === null) {
                    throw new Error(`position ${i}: continuation byte 0x${char.toString(16)} without a start byte`);
                }

                assembly = ((assembly << 6) | (char & 0b00111111));
                --contExpected;
                if (contExpected === 0) {
                    // we are done

                    // verify correctness
                    // (only the shortest encoding is valid)
                    if (assembly <= 0x7F) {
                        throw new Error(`position ${i}: end of ${initialContExpected+1}-byte sequence encoding a 1-byte value`);
                    } else if (assembly <= 0x7FF) {
                        if (initialContExpected != 1) {
                            throw new Error(`position ${i}: end of ${initialContExpected+1}-byte sequence encoding a 2-byte value`);
                        }
                    } else if (assembly <= 0xFFFF) {
                        if (initialContExpected != 2) {
                            throw new Error(`position ${i}: end of ${initialContExpected+1}-byte sequence encoding a 3-byte value`);
                        }
                    }

                    ret.push(assembly);

                    // reset
                    assembly = null;
                    initialContExpected = contExpected = 0;
                }
            } else {
                // normal byte
                if (assembly !== null) {
                    throw new Error(`position ${i}: unexpected low byte 0x${char.toString(16)} within a ${initialContExpected+1}-byte sequence`);
                }

                ret.push(char);
            }
        }

        if (contExpected > 0) {
            throw new Error(`shorted ${initialContExpected+1}-byte sequence at end`);
        }

        return ret;
    }

    function toUtf8(codePoints: number[]): string {
        let ret: string = "";

        for (let i: number = 0; i < codePoints.length; ++i) {
            let char: number = codePoints[i];
            if (char < 0x0000 || char >= 0x10FFFF) {
                throw new Error(`position ${i}: invalid code point 0x${char.toString(16)}`);
            }

            if (char >= 0x10000) {
                // four bytes
                ret += String.fromCharCode(
                    0b11110000 | ((char >>> 18) & 0b00000111),
                    0b10000000 | ((char >>> 12) & 0b00111111),
                    0b10000000 | ((char >>>  6) & 0b00111111),
                    0b10000000 | ((char >>>  0) & 0b00111111),
                );
            } else if (char >= 0x0800) {
                // three bytes
                ret += String.fromCharCode(
                    0b11100000 | ((char >>> 12) & 0b00001111),
                    0b10000000 | ((char >>>  6) & 0b00111111),
                    0b10000000 | ((char >>>  0) & 0b00111111),
                );
            } else if (char >= 0x0080) {
                // two bytes
                ret += String.fromCharCode(
                    0b11000000 | ((char >>>  6) & 0b00011111),
                    0b10000000 | ((char >>>  0) & 0b00111111),
                );
            } else {
                // one byte
                ret += String.fromCharCode(char);
            }
        }

        return ret;
    }

    function checkArray<T>(expected: T[], obtained: T[]): void {
        if (expected.length != obtained.length) {
            throw new Error(`assertion failed: expected ${expected.length} elements, got ${obtained.length}`);
        }
        for (let i = 0; i < expected.length; ++i) {
            if (expected[i] !== obtained[i]) {
                throw new Error(`assertion failed: elements at position ${i} differ (expected ${expected[i]}, obtained ${obtained[i]})`);
            }
        }
    }

    function check<T>(expected: T, obtained: T): void {
        if (expected !== obtained) {
            throw new Error(`assertion failed: expected ${expected}, obtained ${obtained}`);
        }
    }

    function checkThrow(func: () => void): void {
        let thrown: boolean = false;
        try {
            func();
        } catch (ex) {
            thrown = true;
        }

        if (!thrown) {
            throw new Error(`assertion failed: did not throw`);
        }
    }

    export function utfTests() {
        // low ASCII
        checkArray([0x4C, 0x4F, 0x4C], fromUtf16("LOL"));
        checkArray([0x4C, 0x4F, 0x4C], fromUtf8("LOL"));
        check("LOL", toUtf8([0x4C, 0x4F, 0x4C]));
        check("LOL", toUtf16([0x4C, 0x4F, 0x4C]));

        // Latin Extended-A
        checkArray([0x0159, 0x0161], fromUtf16("\u0159\u0161"));
        checkArray([0x0159, 0x0161], fromUtf8("\u00C5\u0099\u00C5\u00A1"));
        check("\u00C5\u0099\u00C5\u00A1", toUtf8([0x0159, 0x0161]));
        check("\u0159\u0161", toUtf16([0x0159, 0x0161]));

        // Currency Symbols
        checkArray([0x20AC, 0x20A9], fromUtf16("\u20AC\u20A9"));
        checkArray([0x20AC, 0x20A9], fromUtf8("\u00E2\u0082\u00AC\u00E2\u0082\u00A9"));
        check("\u20AC\u20A9", toUtf16([0x20AC, 0x20A9]));
        check("\u00E2\u0082\u00AC\u00E2\u0082\u00A9", toUtf8([0x20AC, 0x20A9]));

        // Miscellaneous Symbols and Pictographs
        checkArray([0x1F3CD, 0x1F3C1], fromUtf16("\uD83C\uDFCD\uD83C\uDFC1"));
        checkArray([0x1F3CD, 0x1F3C1], fromUtf8("\u00F0\u009F\u008F\u008D\u00F0\u009F\u008F\u0081"));
        check("\uD83C\uDFCD\uD83C\uDFC1", toUtf16([0x1F3CD, 0x1F3C1]));
        check("\u00F0\u009F\u008F\u008D\u00F0\u009F\u008F\u0081", toUtf8([0x1F3CD, 0x1F3C1]));

        // and now, some fun invalid stuff

        // leading surrogate without trailing surrogate; trailing surrogate without leading surrogate
        checkThrow(() => fromUtf16("abc\uD9D9def"));
        checkThrow(() => fromUtf16("abc\uDCDCdef"));

        // inverted surrogate pair; broken up surrogate pair
        checkThrow(() => fromUtf16("abc\uDFCD\uD83Cdef"));
        checkThrow(() => fromUtf16("abc\uD83Cq\uDFCDdef"));

        // leading surrogate at end
        checkThrow(() => fromUtf16("abc\uD83C"));

        // two leading UTF-8 bytes after each other; continuation byte without leading byte
        checkThrow(() => fromUtf8("\u00C5\u00C5"));
        checkThrow(() => fromUtf8("\u0099\u0099"));

        // shorted UTF-8 sequence; shorted UTF-8 sequence at end
        checkThrow(() => fromUtf8("\u00F0\u009F\u008F\u00F0\u009F\u008F\u0081"));

        // longer-than-shortest-encoding of NUL
        checkThrow(() => fromUtf8("\u00C0\u0080"));
        checkThrow(() => fromUtf8("\u00E0\u0080\u0080"));
        checkThrow(() => fromUtf8("\u00F0\u0080\u0080\u0080"));
    }
}
