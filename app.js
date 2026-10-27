const searchBox = document.getElementById('search-events');
const riskFilter = document.getElementById('risk-filter');
function filterEvents(){
  const q=(searchBox?.value||'').toLowerCase().trim(); const risk=riskFilter?.value||'all'; let shown=0;
  document.querySelectorAll('#event-table tbody tr').forEach(row=>{const matchQ=(row.dataset.search||'').includes(q);const matchRisk=risk==='all'||row.dataset.risk===risk;const visible=matchQ&&matchRisk;row.style.display=visible?'':'none';if(visible)shown++;});
  const empty=document.getElementById('no-match');if(empty)empty.classList.toggle('hidden',shown!==0);
}
searchBox?.addEventListener('input',filterEvents);riskFilter?.addEventListener('change',filterEvents);
const log=document.getElementById('chat-log'), form=document.getElementById('chat-form'), input=document.getElementById('chat-input');
const voiceToggle=document.getElementById('voice-toggle'), voiceListen=document.getElementById('voice-listen'), voiceStatus=document.getElementById('voice-status'), robotStatus=document.getElementById('robot-status');
let speakReplies=true;
function speak(text){
  if(!speakReplies || !('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const utterance=new SpeechSynthesisUtterance(text); utterance.rate=1; utterance.pitch=1.08; utterance.volume=0.9;
  const voices=window.speechSynthesis.getVoices();
  const english=voices.find(v=>/^en(-|_)/i.test(v.lang)); if(english) utterance.voice=english;
  window.speechSynthesis.speak(utterance);
}
function bubble(text,who){const el=document.createElement('div');el.className='bubble '+who;el.textContent=text;log.appendChild(el);log.scrollTop=log.scrollHeight;return el;}
async function ask(message){
  if(!message.trim())return; bubble(message,'user'); input.value=''; input.disabled=true;
  if(robotStatus)robotStatus.textContent='Thinking through the event…'; document.querySelector('.robot-stage')?.classList.add('robot-thinking');
  try{
    const res=await fetch('/api/assistant',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message})});
    if(!res.ok) throw new Error('Request failed'); const data=await res.json(); const answer=data.answer||'No answer returned.'; bubble(answer,'bot'); speak(answer);
    if(robotStatus)robotStatus.textContent='Analysis ready. I can explain the next safe step.';
  }catch(e){const answer='Assistant request failed. Please refresh the dashboard and try again.';bubble(answer,'bot');speak(answer);if(robotStatus)robotStatus.textContent='Connection issue — try again.';}
  finally{input.disabled=false;input.focus();document.querySelector('.robot-stage')?.classList.remove('robot-thinking');}
}
form?.addEventListener('submit',e=>{e.preventDefault();ask(input.value);});
document.querySelectorAll('[data-prompt]').forEach(btn=>btn.addEventListener('click',()=>ask(btn.dataset.prompt)));
voiceToggle?.addEventListener('click',()=>{speakReplies=!speakReplies;voiceToggle.classList.toggle('active',speakReplies);voiceToggle.setAttribute('aria-pressed',String(speakReplies));voiceToggle.textContent=speakReplies?'🔊 Voice replies: On':'🔇 Voice replies: Off';if(!speakReplies&&'speechSynthesis'in window)window.speechSynthesis.cancel();if(voiceStatus)voiceStatus.textContent=speakReplies?'Spoken replies enabled.':'Spoken replies muted.';});
const SpeechRecognition=window.SpeechRecognition||window.webkitSpeechRecognition;
if(voiceListen){
  if(!SpeechRecognition){voiceListen.title='Speech recognition is not supported by this browser';if(voiceStatus)voiceStatus.textContent='Voice input is not supported here; type your question instead.';}
  voiceListen.addEventListener('click',()=>{
    if(!SpeechRecognition){if(voiceStatus)voiceStatus.textContent='Try a supported browser such as desktop Chrome, or type below.';return;}
    const recognition=new SpeechRecognition();recognition.lang='en-IN';recognition.interimResults=false;recognition.maxAlternatives=1;
    voiceListen.disabled=true;voiceListen.textContent='🎙️ Listening…';if(voiceStatus)voiceStatus.textContent='Listening — say your question clearly.';
    recognition.onresult=e=>{const transcript=e.results[0][0].transcript;input.value=transcript;if(voiceStatus)voiceStatus.textContent='Heard: '+transcript;ask(transcript);};
    recognition.onerror=()=>{if(voiceStatus)voiceStatus.textContent='Microphone unavailable or permission denied. You can type instead.';};
    recognition.onend=()=>{voiceListen.disabled=false;voiceListen.textContent='🎙️ Speak to Bot';};
    try{recognition.start();}catch(e){voiceListen.disabled=false;voiceListen.textContent='🎙️ Speak to Bot';if(voiceStatus)voiceStatus.textContent='Could not start microphone. Try again.';}
  });
}
function updateClock(){const el=document.getElementById('local-clock');if(el)el.textContent=' · Browser time: '+new Date().toLocaleString();}
updateClock();setInterval(updateClock,1000);
