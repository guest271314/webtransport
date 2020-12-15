async function webTransportEspeakNG(text) {
  const url = 'quic-transport://localhost:4433/tts';
  try {
    const transport = new WebTransport(url);
    await transport.ready;
    const sender = await transport.createUnidirectionalStream();
    const writer = sender.writable.getWriter();
    const encoder = new TextEncoder('utf-8');
    let data = encoder.encode(text);
    await writer.write(data);
    console.log('writer close', await writer.close());
    const reader = transport.incomingUnidirectionalStreams.getReader();
    const result = await reader.read();
    if (result.done) {
      console.log(result);
      return;
    }
    let stream = result.value;
    console.log({ stream });
    const { readable } = stream;
    const ac = new AudioContext({
      sampleRate: 22050,
      latencyHint: 1,
    });
    const msd = new MediaStreamAudioDestinationNode(ac);
    const { stream: mediaStream } = msd;
    const [track] = mediaStream.getAudioTracks();
    track.onmute = track.onunmute = track.onended = (e) => console.log(e);
    mediaStream.oninactive = (e) => console.log(e);
    ac.onstatechange = (e) => console.log(ac.state);
    const ab = await new Response(readable).arrayBuffer();
    await new Promise(async (resolve) => {
      const uint16 = new Uint16Array(ab.slice(44));
      // https://stackoverflow.com/a/35248852
      const floats = (function int16ToFloat32(inputArray) {
        const output = new Float32Array(inputArray.length);
        for (let i = 0; i < output.length; i++) {
          const int = inputArray[i];
          // If the high bit is on, then it is a negative number, and actually counts backwards.
          const float =
            int >= 0x8000 ? -(0x10000 - int) / 0x8000 : int / 0x7fff;
          output[i] = float;
        }
        return output;
      })(uint16);
      const buffer = new AudioBuffer({
        numberOfChannels: 1,
        length: floats.byteLength,
        sampleRate: ac.sampleRate,
      });
      console.log(floats);
      buffer.getChannelData(0).set(floats);
      const absn = new AudioBufferSourceNode(ac, { buffer });
      console.log(buffer);
      const source = new MediaStreamAudioSourceNode(ac, { mediaStream });
      absn.connect(msd);
      // https://stackoverflow.com/a/46781986
      // TODO: stop playback at EOF/EOS without detect silence
      // using AnalyserNode or requestAnimationFrame to handle
      // SSML <break time="5s">
      const analyser = new AnalyserNode(ac);
      absn.connect(analyser);
      let silence_delay = 200;
      let min_decibels = -80;
      analyser.minDecibels = min_decibels;
      const data = new Uint8Array(analyser.frequencyBinCount); // will hold our data
      let silence_start = performance.now();
      let triggered = false; // trigger only once per silence event
      async function loop(time) {
        analyser.getByteFrequencyData(data); // get current data
        if (data.some((v) => v)) {
          // if there is data above the given db limit
          if (triggered) {
            triggered = false;
          }
          silence_start = time; // set it to now
        }
        if (!triggered && time - silence_start > silence_delay) {
          triggered = true;
          absn.stop(ac.currentTime);
          return;
        }
        requestAnimationFrame(loop); // we'll loop every 60th of a second to check
      }
      loop(performance.now());
      console.log(msd, source);
      source.connect(ac.destination);
      await ac.resume();
      absn.start();
      absn.onended = (e) => {
        console.log(e);
        track.stop();
        [msd, source, absn].forEach((node) => node.disconnect());
        console.log(msd, source, track);
        resolve(ac.close());
      };
    });
    console.log({ reader, transport });
    await reader.cancel();
    await transport.close();
    return transport.closed
      .then((_) => {
        console.log('Connection closed normally.');
        return 'done';
      })
      .catch((e) => {
        console.error(e.message);
        console.trace();
      });
  } catch (e) {
    console.error(e);
    console.trace();
  }
}
