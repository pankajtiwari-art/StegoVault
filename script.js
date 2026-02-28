/**
 * STEGOVAULT v6.0 ENGINE
 * Includes: Crypto, Stego, UI, Utils, Logger
 */

const App = (function() {

    // --- CONFIG ---
    const CFG = {
        iter: 100000, 
        algo: 'AES-GCM', 
        saltLen: 16, 
        ivLen: 12,
        markers: { 
            start: '\u2060\u200B\u200C\u2060', 
            end: '\u2060\u200C\u200B\u2060' 
        }
    };

    let burnInterval = null;
    let currentData = null;
    let failedAttempts = 0; 

    // --- LOGGER ---
    const Logger = {
        log: (msg, type='info') => {
            const t = document.getElementById('terminal');
            const ts = new Date().toLocaleTimeString();
            const cls = type==='error'?'l-err':type==='warn'?'l-warn':type==='success'?'l-success':'l-info';
            const line = `<div class="log-line"><span class="log-ts">[${ts}]</span> <span class="${cls}">${msg}</span></div>`;
            t.innerHTML = line + t.innerHTML;
            
            // Auto-scroll to top
            t.scrollTop = 0;
        },
        clear: () => document.getElementById('terminal').innerHTML = ''
    };

    // --- UTILS ---
    const Utils = {
        compress: async (str) => {
            const s = new Blob([str]).stream().pipeThrough(new CompressionStream('gzip'));
            return new Uint8Array(await new Response(s).arrayBuffer());
        },
        decompress: async (u8) => {
            const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
            return await new Response(s).text();
        },
        checkStrength: (pw) => {
            const s = document.querySelectorAll('.strength-seg');
            const t = document.getElementById('str-text');
            s.forEach(e => e.style.background = '#222');
            
            let score = 0;
            if(pw.length > 5) score++;
            if(pw.length > 8) score++;
            if(/[A-Z]/.test(pw) && /[0-9]/.test(pw)) score++;
            if(/[^A-Za-z0-9]/.test(pw)) score++;

            const colors = ['#222', '#ff0055', '#ffcc00', '#00f3ff', '#00ff9d'];
            const texts = ['None', 'Weak', 'Medium', 'Strong', 'Unbreakable'];
            
            for(let i=0; i<score; i++) {
                s[i].style.background = colors[score];
                s[i].style.background = `linear-gradient(90deg, ${colors[score]}, ${colors[score]}80)`;
            }
            
            t.textContent = "Strength: " + texts[score];
            t.style.color = colors[score];
        },
        
        updateVisualization: (cover, secret) => {
            const coverLen = cover.length;
            const secretLen = secret.length;
            const totalLen = coverLen + secretLen;
            
            const coverPercent = (coverLen / totalLen) * 100;
            const secretPercent = (secretLen / totalLen) * 100;
            
            document.getElementById('vis-cover').style.width = `${coverPercent}%`;
            document.getElementById('cover-size').textContent = `${coverLen} chars`;
            document.getElementById('secret-size').textContent = `${secretLen} chars`;
            
            // Calculate steganography efficiency (higher is better)
            const efficiency = Math.min(100, Math.round((secretLen / (coverLen || 1)) * 100));
            document.getElementById('stego-percent').textContent = `${efficiency}% efficiency`;
            
            // Show visualization
            document.getElementById('data-vis').classList.add('show');
        },
        
        animateSuccess: () => {
            const successEl = document.getElementById('enc-success');
            successEl.classList.add('show');
            
            // Add pulse animation
            successEl.style.animation = 'none';
            setTimeout(() => {
                successEl.style.animation = 'pulse 1s 3';
            }, 10);
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                successEl.classList.remove('show');
            }, 5000);
        },

        //Lockdown UI
        updateLockdownUI: (isLocked) => {
            const dot = document.getElementById('sys-dot');
            const txt = document.getElementById('sys-text');
            if (dot && txt) {
                if(isLocked) {
                    dot.style.background = 'var(--neon-red)';
                    dot.style.boxShadow = '0 0 10px var(--neon-red)';
                    txt.innerText = 'SYSTEM LOCKED';
                    txt.style.color = 'var(--neon-red)';
                } else {
                    dot.style.background = 'var(--neon-green)';
                    dot.style.boxShadow = '0 0 5px var(--neon-green)';
                    txt.innerText = 'SYSTEM SECURE';
                    txt.style.color = 'var(--text-muted)';
                }
            }
        }
    };

    // --- CRYPTO MODULE ---
    const Crypto = {
        getKey: async (pw, salt) => {
            const enc = new TextEncoder();
            const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
            return crypto.subtle.deriveKey(
                {name:"PBKDF2", salt, iterations:CFG.iter, hash:"SHA-256"}, 
                k, 
                {name:CFG.algo, length:256}, 
                false, 
                ["encrypt","decrypt"]
            );
        },
        
        encrypt: async (txt, pw, salt) => {
            const key = await Crypto.getKey(pw, salt);
            const iv = crypto.getRandomValues(new Uint8Array(CFG.ivLen));
            const comp = await Utils.compress(txt);
            const encBuf = await crypto.subtle.encrypt({name:CFG.algo, iv}, key, comp);
            
            // Integrity hash
            const hashBuf = await crypto.subtle.digest("SHA-256", comp);
            const hashArr = new Uint8Array(hashBuf).slice(0, 8);

            // Pack: IV(12) + Hash(8) + Cipher
            const res = new Uint8Array(iv.length + 8 + encBuf.byteLength);
            res.set(iv, 0);
            res.set(hashArr, iv.length);
            res.set(new Uint8Array(encBuf), iv.length + 8);
            return res;
        },

        decrypt: async (buf, pw, salt) => {
            const iv = buf.slice(0, CFG.ivLen);
            const checkSum = buf.slice(CFG.ivLen, CFG.ivLen+8);
            const data = buf.slice(CFG.ivLen+8);
            const key = await Crypto.getKey(pw, salt);
            
            const decBuf = await crypto.subtle.decrypt({name:CFG.algo, iv}, key, data);
            
            // Verify Checksum
            const hashBuf = await crypto.subtle.digest("SHA-256", decBuf);
            const newSum = new Uint8Array(hashBuf).slice(0, 8);
            
            for(let i=0; i<8; i++) {
                if(newSum[i] !== checkSum[i]) throw new Error("Integrity Check Failed (Corrupted Data)");
            }

            return await Utils.decompress(decBuf);
        }
    };

    // --- STEGO MODULE ---
    const Stego = {
        toZW: (u8) => {
            let b = ''; 
            u8.forEach(x => b += x.toString(2).padStart(8,'0'));
            return b.split('').map(x => x==='0'?'\u200B':'\u200C').join('');
        },
        
        fromZW: (str) => {
            let b = str.split('').map(x => x==='\u200B'?'0':'1').join('');
            const u8 = []; 
            for(let i=0; i<b.length; i+=8) {
                if(i+8 <= b.length) {
                    u8.push(parseInt(b.substr(i,8), 2));
                }
            }
            return new Uint8Array(u8);
        },
        
        embed: (cover, data) => {
            const cleanCover = cover.trim() || "Secure transmission initiated.";
            return cleanCover + CFG.markers.start + Stego.toZW(data) + CFG.markers.end;
        },
        
        extract: (txt) => {
            const s = txt.indexOf(CFG.markers.start);
            const e = txt.lastIndexOf(CFG.markers.end);
            if(s < 0 || e < 0) return null;
            
            const hidden = txt.substring(s + CFG.markers.start.length, e);
            const cleanHidden = hidden.replace(/[^\u200B\u200C]/g, '');
            
            return Stego.fromZW(cleanHidden);
        }
    };

    // --- ACTIONS ---
    const Actions = {
        loadTemplate: () => {
            const templates = {
                meet: "Meeting Minutes 2024\nAgenda: Review Q3 performance and define OKRs for Q4.\nAttendees: John, Sarah, Mike, Lisa\nKey Points: Budget approved for new initiatives, timeline set for Q4 rollout.",
                sys: "[SYSTEM] Service uptime: 99.9%. All subsystems operational.\nLast backup: 2024-03-15 03:00 UTC\nNext maintenance: 2024-03-22 02:00-04:00 UTC\nAlerts: None",
                chat: "Hey, are we still on for dinner tonight? Let me know.\nI was thinking we could try that new Italian place downtown.\nWhat time works for you? I'm free after 7."
            };
            const v = document.getElementById('tpl-select').value;
            if(templates[v]) {
                document.getElementById('enc-cover').value = templates[v];
                Utils.updateVisualization(templates[v], document.getElementById('enc-secret').value);
            }
        },
        pasteText: async () => {
            try {
                // OS clipboard se raw text padhne ki koshish karega
                const text = await navigator.clipboard.readText();
                document.getElementById('dec-input').value = text;
                Logger.log("Raw text pasted securely from OS clipboard.", 'success');
            } catch (err) {
                // Agar browser permission na de (clipboard read karne ke liye prompt aayega)
                Logger.log("Paste failed: Browser permission denied. Use long-press to paste.", 'error');
            }
        },
         toggleDecoy: () => {
            const decoyBox = document.getElementById('decoy-box');
            const toggleBtn = document.getElementById('decoy-toggle-btn');
            
            decoyBox.classList.toggle('show');
            
            if(decoyBox.classList.contains('show')) {
                // Jab ON ho
                Logger.log("⚠️ DURESS PROTOCOL ARMED: Decoy Layer Activated", 'warn');
                if(toggleBtn) {
                    toggleBtn.innerText = "[ ❌ DISABLE DURESS MODE ]";
                    toggleBtn.style.color = "var(--neon-red)";
                    toggleBtn.style.textShadow = "0 0 10px rgba(255, 0, 85, 0.6)";
                }
            } else {
                // Jab OFF ho
                Logger.log("Duress protocol disabled", 'info');
                if(toggleBtn) {
                    toggleBtn.innerText = "[ + DUAL LAYER MODE ]";
                    toggleBtn.style.color = "var(--neon-blue)";
                    toggleBtn.style.textShadow = "none";
                }
            }
        },
        
        clearEnc: () => {
            ['enc-cover','enc-secret','enc-pass','enc-ttl','decoy-secret','decoy-pass'].forEach(i => {
                document.getElementById(i).value = '';
            });
            
            document.getElementById('enc-success').classList.remove('show');
            document.getElementById('data-vis').classList.remove('show');
            
            Logger.log("Encoding fields reset.", 'info');
        },

        panic: () => {
            // 1. Data turant delete karo
            Actions.clearEnc();
            document.getElementById('dec-input').value = '';
            document.getElementById('dec-pass').value = '';
            document.getElementById('dec-result').value = '';
            document.getElementById('res-panel').style.display = 'none';
            if(burnInterval) clearInterval(burnInterval);
            
            // 2. Terminal me warning do
            Logger.clear();
            Logger.log("⚠️ CRITICAL THREAT DETECTED. INITIATING MELTDOWN...", 'error');
            Logger.log("OVERRIDING KERNEL...", 'error');
            Logger.log("WIPING MEMORY BANKS...", 'error');
            
            // 3. CSS Glitch aur Shake Activate karo
            document.body.classList.add('meltdown-active');
            
            // 4. Matrix Canvas ko Red/Glitch mode me daalo
            const canvas = document.getElementById('matrix-canvas');
            const ctx = canvas.getContext('2d');
            let meltdownInterval = setInterval(() => {
                ctx.fillStyle = `rgba(255, ${Math.random()*50}, ${Math.random()*50}, 0.6)`;
                ctx.fillRect(0, 0, canvas.width, canvas.height);
            }, 60);

            // 5. Screen ke saare text ko randomly scramble karo (Hacker effect)
            const allTextElements = document.querySelectorAll('span, label, .panel-head, button');
            const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;<>?";
            
            let scrambleInterval = setInterval(() => {
                allTextElements.forEach(el => {
                    // Sirf un elements ka text change karo jinke andar aur tags nahi hain
                    if(Math.random() > 0.6 && el.innerText.length > 0 && el.children.length === 0) {
                        let newText = "";
                        for(let i=0; i<el.innerText.length; i++) {
                            newText += chars[Math.floor(Math.random() * chars.length)];
                        }
                        el.innerText = newText;
                    }
                });
            }, 80);

            // 6. System Kill Switch (2.5 seconds ke baad sab off)
            setTimeout(() => {
                clearInterval(meltdownInterval);
                clearInterval(scrambleInterval);
                document.body.classList.remove('meltdown-active');
                
                // Sab kuch chupa do, aur Offline screen dikhao
                document.getElementById('app-frame').style.display = 'none';
                document.getElementById('matrix-canvas').style.display = 'none';
                document.getElementById('offline-screen').classList.add('show');
            }, 2500);
        },


        encrypt: async () => {
            const cover = document.getElementById('enc-cover').value;
            const secret = document.getElementById('enc-secret').value;
            const pass = document.getElementById('enc-pass').value;
            const ttl = document.getElementById('enc-ttl').value;
            const dSec = document.getElementById('decoy-secret').value;
            const dPass = document.getElementById('decoy-pass').value;

            if(!secret || !pass) { 
                Logger.log("Encryption Failed: Secret message and password required", 'error'); 
                return; 
            }

            Logger.log("Initiating Encryption Protocol...", 'info');
            
            // Update visualization
            Utils.updateVisualization(cover, secret);

            try {
                const salt = crypto.getRandomValues(new Uint8Array(CFG.saltLen));
                
                // Checkbox status aur Unique ID generate karo
                const isBurnOnce = document.getElementById('enc-burn-once').checked;
                const payloadId = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);

                // 1. Pack Real payload
                const realPayload = JSON.stringify({ 
                    m: secret, 
                    c: Date.now(), 
                    t: parseInt(ttl) || 0,
                    v: '6.0',
                    id: payloadId,    // Unique Payload ID
                    b: isBurnOnce     // Single-use flag
                });

                const realBlob = await Crypto.encrypt(realPayload, pass, salt);

                // 2. Pack Decoy payload
                let decoyBlob;
                if(dSec && dPass) {
                    const dPayload = JSON.stringify({ 
                        m: dSec, 
                        c: Date.now(), 
                        t: 0,
                        d: true // Mark as decoy
                    });
                    decoyBlob = await Crypto.encrypt(dPayload, dPass, salt);
                    Logger.log("Decoy layer encrypted", 'warn');
                } else {
                    // Random data if no decoy
                    decoyBlob = crypto.getRandomValues(new Uint8Array(32));
                }

                // 3. Combine with length prefix
                const lenBytes = new Uint8Array(4);
                new DataView(lenBytes.buffer).setUint32(0, realBlob.length);
                
                const final = new Uint8Array(salt.length + 4 + realBlob.length + decoyBlob.length);
                let p = 0;
                final.set(salt, p); p += salt.length;
                final.set(lenBytes, p); p += 4;
                final.set(realBlob, p); p += realBlob.length;
                final.set(decoyBlob, p);

                // 4. Embed in cover text
                const stegoText = Stego.embed(cover, final);
                
                // 5. Copy to clipboard
                await navigator.clipboard.writeText(stegoText);
                
                // 6. Show success animation
                Utils.animateSuccess();
                
                // 7. Log success
                const hiddenRatio = ((final.length * 8) / (cover.length || 1)).toFixed(2);
                Logger.log(`Payload embedded successfully. Stego ratio: ${hiddenRatio} bits/char`, 'success');
                Logger.log(`Cover: ${cover.length} chars, Hidden: ${final.length} bytes`, 'info');

            } catch(e) { 
                Logger.log("Encryption Error: " + e.message, 'error'); 
            }
        },

        decrypt: async () => {
            const txt = document.getElementById('dec-input').value;
            const pass = document.getElementById('dec-pass').value;
            const resPanel = document.getElementById('res-panel');
            const resField = document.getElementById('dec-result');
            const intBadge = document.getElementById('integrity-badge');
            const layerInfo = document.getElementById('layer-info');
            
            if(!txt || !pass) {
                Logger.log("Decryption Failed: Missing input or password", 'warn'); 
                return;
            }
            
            // Reset UI
            if(burnInterval) clearInterval(burnInterval);
            resPanel.style.display = 'none';
            resField.value = '';
            intBadge.style.display = 'none';
            layerInfo.style.display = 'none';
            
            Logger.log("Scanning for steganographic data...", 'info');
            // --- KIL-SWITCH CHECK ---
            if (localStorage.getItem('stego_global_lockdown') === 'ACTIVE') {
                resPanel.style.display = 'block';
                resField.value = "⛔ SYSTEM LOCKDOWN ACTIVE.\n\nDecryption engine has been disabled via terminal command. All payloads are treated as incinerated on this device.";
                resField.style.color = "var(--neon-red)";
                intBadge.style.display = 'none';
                document.getElementById('burn-display').innerText = "[ ENGINE OFFLINE ]";
                Logger.log("Intrusion blocked. Decryption engine is under Global Lockdown.", 'error');
                return; 
            }

            try {
                // 1. Extract hidden data
                const rawBuf = Stego.extract(txt);
                if(!rawBuf) throw new Error("No hidden data found in text");
                
                Logger.log(`Hidden data extracted: ${rawBuf.length} bytes`, 'success');

                // 2. Unpack structure
                let p = 0;
                const salt = rawBuf.slice(p, p += CFG.saltLen);
                const lenReal = new DataView(rawBuf.buffer).getUint32(p); p += 4;
                const realBlob = rawBuf.slice(p, p += lenReal);
                const decoyBlob = rawBuf.slice(p);

                let data = null;
                let isDecoy = false;

                 // 3. Try real password first
                try {
                    const json = await Crypto.decrypt(realBlob, pass, salt);
                    data = JSON.parse(json);
                    failedAttempts = 0; // Success pe reset
                    Logger.log("Real payload accessed", 'success');
                } catch(e1) {
                    // Try decoy password
                    try {
                        const json = await Crypto.decrypt(decoyBlob, pass, salt);
                        data = JSON.parse(json);
                        isDecoy = true;
                        failedAttempts = 0; // Success pe reset
                        Logger.log("Decoy payload accessed", 'warn');
                    } catch(e2) { 
                        // --- BRUTE-FORCE LOGIC ---
                        failedAttempts++;
                        if (failedAttempts >= 3) {
                            localStorage.setItem('stego_global_lockdown', 'ACTIVE');
                            failedAttempts = 0; // Agli baar ke liye reset
                            throw new Error("🚨 BRUTE-FORCE DETECTED. GLOBAL LOCKDOWN INITIATED.");
                        }
                        throw new Error(`Invalid Password. Attempts remaining: ${3 - failedAttempts}`); 
                    }
                }

                // 4. Show layer info if decoy
                if(isDecoy) {
                    layerInfo.style.display = 'block';
                }

                // -- SINGLE-READ BURN CHECK --
                if (data.b && data.id) {
                    const burnKey = 'stego_burn_' + data.id;
                    
                    // Check agar pehle padha ja chuka hai
                    if (localStorage.getItem(burnKey)) {
                        resPanel.style.display = 'block';
                        resField.value = "⛔ CRITICAL ERROR: PAYLOAD ALREADY CONSUMED.\n\nThis was a single-use transmission. The data has been permanently incinerated from memory. Access Denied.";
                        resField.style.color = "var(--neon-red)";
                        intBadge.style.display = 'none';
                        document.getElementById('burn-display').innerText = "[ COMPROMISED ]";
                        Logger.log("Intrusion Attempt: Tried to access a consumed single-use payload.", 'error');
                        return; 
                    } else {
                        // Agar first time hai, toh padhne do aur memory mein mark kar do
                        localStorage.setItem(burnKey, 'true');
                        document.getElementById('burn-display').innerText = "[ 1-TIME READ BURNED ]";
                        document.getElementById('burn-display').style.color = "var(--neon-red)";
                        Logger.log("Single-use payload consumed. ID permanently logged as BURNED.", 'warn');
                    }
                }

                // 5. TTL Check

                if(data.t > 0) {
                    const exp = data.c + (data.t * 1000);
                    if(Date.now() > exp) {
                        resPanel.style.display = 'block';
                        resField.value = "⛔ DATA INCINERATED (TTL EXPIRED)";
                        resField.style.color = "var(--neon-red)";
                        intBadge.style.display = 'none';
                        Logger.log("TTL Exceeded. Data auto-wiped.", 'error');
                        return;
                    }
                    Actions.startBurn(exp);
                }

                // 6. Success - Show with hacker effect
                resPanel.style.display = 'block';
                intBadge.style.display = 'block';
                Logger.log("Payload decrypted successfully", 'success');
                
                // Hacker text effect
                const original = data.m;
                let result = '';
                const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
                
                let i = 0;
                const hackerInterval = setInterval(() => {
                    // Build string with gradually revealed characters
                    result = original.split('').map((char, idx) => {
                        if(idx < i) {
                            return original[idx];
                        }
                        // Random char for unrevealed positions
                        return chars[Math.floor(Math.random() * chars.length)];
                    }).join('');
                    
                    resField.value = result;
                    
                    i += 0.3; // Speed of reveal
                    
                    if(i >= original.length) {
                        clearInterval(hackerInterval);
                        // Final reveal with color effect
                        resField.value = original;
                        resField.classList.add('hacker-mode');
                        setTimeout(() => {
                            resField.classList.remove('hacker-mode');
                        }, 2000);
                    }
                }, 30);

            } catch(e) {
                resPanel.style.display = 'block';
                // Ab generic error ki jagah hum actual remaining attempts ya lockdown message dikhayenge
                resField.value = "⛔ " + e.message; 
                resField.style.color = "var(--neon-red)";
                intBadge.style.display = 'none';
                Logger.log(e.message, 'error');
                
                // --- BRUTE-FORCE PENALTY LOGIC ---
                if (e.message && e.message.includes("BRUTE-FORCE")) {
                    // Fields ko turant wipe kar do taaki aur try na kar sake
                    document.getElementById('dec-input').value = '';
                    document.getElementById('dec-pass').value = '';
                    document.getElementById('burn-display').innerText = "[ OFFLINE ]";
                    
                    // Dramatic screen shake effect
                    document.body.style.animation = "frameShake 0.4s";
                    setTimeout(() => { document.body.style.animation = ""; }, 400);
                }
            }
        },

        startBurn: (exp) => {
            const burnDisplay = document.getElementById('burn-display');
            
            const tick = () => {
                const left = Math.ceil((exp - Date.now()) / 1000);
                if(left <= 0) {
                    clearInterval(burnInterval);
                    document.getElementById('dec-result').value = "⛔ DATA INCINERATED";
                    burnDisplay.innerText = "";
                    Logger.log("Data auto-wiped (TTL expired)", 'error');
                } else {
                    // Color changes as time runs out
                    if(left < 10) {
                        burnDisplay.style.color = 'var(--neon-red)';
                        burnDisplay.style.animation = 'pulse 0.5s infinite';
                    } else if(left < 30) {
                        burnDisplay.style.color = 'var(--neon-amber)';
                    }
                    
                    burnDisplay.innerText = `[ AUTO-WIPE: ${left}s ]`;
                }
            };
            
            tick();
            burnInterval = setInterval(tick, 1000);
        }
    };
    // --- BOT MODULE ---
    const Bot = {
        toggle: () => {
            const w = document.getElementById('stego-bot-window');
            w.classList.toggle('show');
            if(w.classList.contains('show')) document.getElementById('bot-input').focus();
        },
        handleEnter: (e) => {
            if(e.key === 'Enter') Bot.send();
        },
        send: () => {
            const input = document.getElementById('bot-input');
            const text = input.value.trim();
            if(!text) return;
            
            Bot.appendMsg(text, 'user');
            input.value = '';
            
            // Artificial delay to make it feel like an AI processing
            setTimeout(() => { Bot.reply(text.toLowerCase()); }, 600);
        },
        appendMsg: (text, sender) => {
            const chat = document.getElementById('bot-chat');
            const div = document.createElement('div');
            div.className = `bot-msg ${sender}`;
            div.innerHTML = text;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        },
        reply: (q) => {
             // --- 🔴 COMMAND EXECUTION ENGINE ---
            if (q === '/panic') {
                Bot.appendMsg("⚠️ INITIATING KERNEL PANIC...", 'bot');
                setTimeout(() => {
                    App.Actions.panic();
                    Bot.toggle();
                }, 800);
                return;
            }

            if (q === '/disable') {
                // System ko permanently (locally) lock karna
                localStorage.setItem('stego_global_lockdown', 'ACTIVE');
                App.Utils.updateLockdownUI(true);
                
                App.Actions.clearEnc();
                document.getElementById('dec-input').value = '';
                document.getElementById('dec-pass').value = '';
                document.getElementById('dec-result').value = '';
                document.getElementById('res-panel').style.display = 'none';
                if(window.burnInterval) clearInterval(window.burnInterval);
                
                App.Logger.log("⛔ GLOBAL LOCKDOWN INITIATED. ALL DECRYPTIONS BLOCKED.", 'err');
                Bot.appendMsg("⚠️ Lockdown Active. The decryption engine is now offline. The terminal will refuse to decrypt ANY payload. Type <strong>/enable</strong> to restore functionality.", 'bot');
                return;
            }

            if (q === '/enable') {
                // System ka lock hatana
                localStorage.removeItem('stego_global_lockdown');
                App.Utils.updateLockdownUI(false);
                App.Logger.log("✅ GLOBAL LOCKDOWN LIFTED. ENGINE RESTORED.", 'success');
                Bot.appendMsg("System restored. Decryption engine is back online.", 'bot');
                return;
            }

            if (q === '/clear') {
                const chat = document.getElementById('bot-chat');
                chat.innerHTML = '<div class="bot-msg bot">Terminal memory cleared. System ready. Commands: /panic, /disable, /enable, /clear.</div>';
                return;
            }

            // --- 🟢 NORMAL SMART CHAT ENGINE ---
            const match = (words) => words.some(w => new RegExp('\\b' + w + '\\b', 'i').test(q));

            
            let res = "Query not recognized. Ask about: 'encryption', 'decryption', 'duress', 'history', 'creator'. Or execute commands: <strong>/panic</strong>, <strong>/disable</strong>, <strong>/clear</strong>.";
            
            // 1. Greetings
            if(match(['hi', 'hello', 'hey', 'status', 'wake up', 'system', 'ping'])) {
                res = "System is online. All cryptographic modules are loaded. Try executing /panic or /disable, or ask me a question.";
            }
            // 2. Creator
            else if(match(['creator', 'who made', 'who created', 'developer', 'author', 'pankaj', 'create', 'birth'])) {
                res = "StegoVault was engineered by Pankaj Tiwari. He is a developer experienced in creating games and websites, and the author of 'Control Psychology: The Illusionary Game'.";
            }
            // 3. History
            else if(match(['history', 'what is this', 'about stegovault', 'purpose', 'why are you'])) {
                res = "StegoVault Black Ops Edition is a tactical offline steganography tool. It hides AES-256 encrypted payloads inside invisible zero-width characters.";
            }
            // 4. Encrypt
            else if(match(['encrypt', 'how to hide', 'how does it work', 'encoding'])) {
                res = "Encryption Protocol: Compress payload -> Encrypt with AES-GCM -> Convert to zero-width characters -> Embed into cover text.";
            }
            // 5. Decrypt
            else if(match(['decrypt', 'extract', 'read', 'unlock'])) {
                res = "Decryption Protocol: Extract zero-width binary -> Verify HMAC-SHA256 checksum -> Decrypt using provided key.";
            }
            // 6. Duress
            else if(match(['duress', 'decoy', 'fake', 'dual layer', 'interrogation'])) {
                res = "The Duress Protocol creates a secondary payload. If forced to surrender a password, giving the Decoy Key reveals fake data, keeping the real secret safe.";
            }
            // 7. Panic Info
            else if(match(['panic mode', 'what is panic', 'meltdown', 'kill switch'])) {
                res = "Panic Mode triggers a memory wipe and visual meltdown. You can double-tap 'ESC' or type <strong>/panic</strong> right here to trigger it.";
            }
            // 8. Burn
            else if(match(['burn', 'ttl', 'expire', 'single use', 'destroy'])) {
                res = "Payloads can be rigged with a TTL timer or Single-Read flag. Once compromised, they are permanently incinerated.";
            }
            // 9. Integrity
            else if(match(['integrity', 'hash', 'corrupt', 'tamper', 'sha256'])) {
                res = "StegoVault uses HMAC-SHA256. If a social media platform truncates even a single bit of your hidden data, the system halts to prevent corruption.";
            }
            // 10. Help
            else if(match(['help', 'commands', 'what can you do', 'menu'])) {
                res = "Commands: <br><strong>/panic</strong> - Trigger Meltdown<br><strong>/disable</strong> - Wipe all instances<br><strong>/clear</strong> - Clean chat<br><br>Or ask me general questions about the system.";
            }
            // more here...

            Bot.appendMsg(res, 'bot');
        }

    };

    // --- INIT ---
    function init() {
        // Boot hote hi lockdown check karega
        if (localStorage.getItem('stego_global_lockdown') === 'ACTIVE') {
            Utils.updateLockdownUI(true);
        }
        
        // Enhanced Matrix Background
        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const chars = "01";
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);
        
        // More colorful matrix effect
        function drawMatrix() {
            // Semi-transparent black overlay for trailing effect
            ctx.fillStyle = 'rgba(5, 5, 5, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Draw characters
            drops.forEach((y, i) => {
                // Random character
                const text = chars[Math.floor(Math.random() * chars.length)];
                
                // Color gradient (green to blue)
                const hue = 120 + Math.random() * 120; // Green to blue
                ctx.fillStyle = `hsla(${hue}, 100%, 50%, 0.8)`;
                ctx.font = `${fontSize}px monospace`;
                
                // Draw character
                ctx.fillText(text, i * fontSize, y * fontSize);
                
                // Reset drop if it reaches bottom with some randomness
                if(y * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                
                drops[i]++;
            });
        }
        
        setInterval(drawMatrix, 50);
        
        // Resize handler
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
        
        // --- UPGRADED CIPHER HOVER/TAP EFFECT ---
        const logoContainer = document.getElementById('logo-container');
        const logoText = document.getElementById('logo-text');
        
        const originalHTML = 'STEGO<span style="color:var(--neon-blue)">VAULT</span>';
        const targetText = 'STEGOVAULT';
        const cipherChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*<>?";
        
        // Cyberpunk colors ka array
        const neonColors = [
            'var(--neon-blue)', 
            'var(--neon-green)', 
            'var(--neon-red)', 
            'var(--neon-purple)', 
            'var(--neon-amber)'
        ];
        
        let cipherInterval = null;
        let isAnimating = false;

        const triggerCipher = (e) => {
            if(e) e.preventDefault(); 
            if(isAnimating) return;
            
            isAnimating = true;
            let iteration = 0;
            clearInterval(cipherInterval);
            
            // Effect trigger hote hi thoda scale-up aur shake effect dena
            logoContainer.style.transform = "scale(1.05)";
            logoContainer.style.transition = "transform 0.1s";
            
            cipherInterval = setInterval(() => {
                // innerHTML use kar rahe hain taaki span tags render ho sakein
                logoText.innerHTML = targetText
                    .split("")
                    .map((letter, index) => {
                        if(index < iteration) {
                            // Jo letters decode ho chuke hain, wo normal white rahenge
                            return `<span style="color: #fff; text-shadow: 0 0 5px #fff;">${targetText[index]}</span>`;
                        }
                        // Jo letters abhi scramble ho rahe hain, unko random color aur glow do
                        const randomChar = cipherChars[Math.floor(Math.random() * cipherChars.length)];
                        const randomColor = neonColors[Math.floor(Math.random() * neonColors.length)];
                        
                        return `<span style="color: ${randomColor}; text-shadow: 0 0 10px ${randomColor};">${randomChar}</span>`;
                    })
                    .join("");
                
                if(iteration >= targetText.length){ 
                    clearInterval(cipherInterval);
                    // Animation khatam hone par sab wapas normal
                    logoText.innerHTML = originalHTML; 
                    logoContainer.style.transform = "scale(1)";
                    isAnimating = false;
                }
                
                iteration += 1/5; // Speed (1/3 ka matlab har letter 3 frame tak scramble hoga)
            }, 30);
        };
        
        // Desktop Trigger
        logoContainer.addEventListener('mouseenter', triggerCipher);
        
        // Mobile Triggers
        logoContainer.addEventListener('touchstart', triggerCipher, {passive: false});
        logoContainer.addEventListener('click', triggerCipher);
        
        // --- Page load hote hi apne aap trigger karna ---
        setTimeout(() => {
            triggerCipher();
        }, 800); // 800ms ka delay taaki UI load hone ke baad effect aaye
        // ------------------------------------------
        // Burn Toggle Magic Text Effect
        const burnInput = document.getElementById('enc-burn-once');
        const burnTextSpan = document.getElementById('burn-text-span');
        
        burnInput.addEventListener('change', function() {
            if(this.checked) {
                burnTextSpan.innerText = "🔥 LETHAL PAYLOAD ARMED 🔥";
            } else {
                burnTextSpan.innerText = "BURN AFTER READING";
            }
        });

        // Escape key panic listener
        let escCount = 0;
        document.addEventListener('keydown', (e) => {
            if(e.key === "Escape") {
                escCount++;
                if(escCount === 2) {
                    Actions.panic();
                    escCount = 0;
                }
                setTimeout(() => { escCount = 0; }, 500);
            }
        });
        
        // Update visualization on input
        document.getElementById('enc-cover').addEventListener('input', function() {
            Utils.updateVisualization(this.value, document.getElementById('enc-secret').value);
        });
        
        document.getElementById('enc-secret').addEventListener('input', function() {
            Utils.updateVisualization(document.getElementById('enc-cover').value, this.value);
        });
        
        Logger.log("System initialized successfully", 'success');
        Logger.log("Ready for secure transmission", 'info');
    }

    return { 
        router: (p) => {
            // Hide all views
            document.querySelectorAll('.view-port').forEach(e => e.classList.remove('active'));
            // Show selected view
            document.getElementById('view-' + p).classList.add('active');
            
            // Update navigation
            document.querySelectorAll('.nav-btn').forEach(e => e.classList.remove('active'));
            document.getElementById('nav-' + p).classList.add('active');
            
            // Update page title
            const titles = {
                encode: 'Encryption Protocol',
                decode: 'Decryption Protocol', 
                logs: 'System Terminal',
                about: 'Operational Intel'
            };
            document.getElementById('page-title').innerText = titles[p] || p.toUpperCase();
        }, 
        Actions, 
        Utils, 
        Logger,
        Bot,
        init 
    };

})();

// Initialize on load
window.onload = App.init;
