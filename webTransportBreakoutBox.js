async function webTransportBreakoutBox(text) {
  const url = 'quic-transport://localhost:4433/tts';
  try {
    const transport = new WebTransport(url);
    await transport.ready;
    const initial = 1; // 6.4KiB (65536)
    const maximum = 500; // 32 KiB
    let readOffset = 0;
    let writeOffset = 0;
    let duration = 0;
    let init = false;
    // TODO process odd length Uint8Array without writing to Memory
    const memory = new WebAssembly.Memory({
      initial,
      maximum,
      shared: true,
    });
    const sender = await transport.createUnidirectionalStream();
    const writer = sender.writable.getWriter();
    const encoder = new TextEncoder('utf-8');
    const data = encoder.encode(
      `espeak-ng -m --stdout "${text}"`
    );
    await writer.write(data);
    await writer.close();
    const reader = transport.incomingUnidirectionalStreams.getReader();
    const result = await reader.read();
    const transportStream = result.value;
    const { readable } = transportStream;
    const ac = new AudioContext({
      sampleRate: 22050,
      latencyHint: 0,
    });
    const audio = document.querySelector('audio');
    const msd = new MediaStreamAudioDestinationNode(ac, {
      channelCount: 1,
    });
    const { stream } = msd;
    const [track] = stream.getAudioTracks();
    const osc = new OscillatorNode(ac, { frequency: 0 });
    const processor = new MediaStreamTrackProcessor(track);
    const generator = new MediaStreamTrackGenerator({ kind: 'audio' });
    const { writable } = generator;
    const { readable: audioReadable } = processor;
    const audioWriter = writable.getWriter();
    const mediaStream = new MediaStream([generator]);
    const audioReader = audioReadable.getReader();
    audio.srcObject = mediaStream;
    osc.connect(msd);
    osc.start();
    track.onmute = track.onunmute = track.onended = (e) => console.log(e);
    // const recorder = new MediaRecorder(mediaStream);
    // recorder.ondataavailable = ({ data }) => console.log(URL.createObjectURL(data));
    // recorder.start();
    await Promise.all([
      readable.pipeTo(
        new WritableStream({
          async write(value, c) {
            console.log(
              `Uint8Array.buffer.byteLength: ${value.buffer.byteLength}`
            );
            if (readOffset + value.byteLength > memory.buffer.byteLength) {
              console.log(
                `memory.buffer.byteLength before grow(): ${memory.buffer.byteLength}.`
              );
              memory.grow(3);
              console.log(
                `memory.buffer.byteLength after grow(): ${memory.buffer.byteLength}`
              );
            }
            let sab = new Uint8Array(memory.buffer);
            let i = 0;
            if (!init) {
              init = true;
              i = 44;
            }
            for (; i < value.buffer.byteLength; i++, readOffset++) {
              if (readOffset + 1 >= memory.buffer.byteLength) {
                console.log(
                  `memory.buffer.byteLength before grow() for loop: ${memory.buffer.byteLength}.`
                );
                memory.grow(3);
                console.log(
                  `memory.buffer.byteLength after grow() for loop: ${memory.buffer.byteLength}`
                );
                sab = new Uint8Array(memory.buffer);
              }
              sab[readOffset] = value[i];
            }
          },
          close() {
            console.log('Done writing input stream.');
          },
        })
      ),
      audioReader.read().then(async function process({ value, done }) {
        // avoid clipping start of MediaStreamTrackGenerator output
        if (audio.currentTime < value.buffer.duration * 50) {
          return audioWriter
            .write(value)
            .then(() => audioReader.read().then(process));
        }
        if (writeOffset && writeOffset >= readOffset) {
          // avoid clipping end of MediaStreamTrackGenerator output
          if (audio.currentTime < duration + value.buffer.duration * 100) {
            return audioReader.read().then(process);
          } else {
            msd.disconnect();
            osc.disconnect();
            track.stop();
            audioReader.releaseLock();
            await audioReadable.cancel();
            audioWriter.releaseLock();
            await writable.abort();
            await writable.closed;
            await ac.close();
            console.log(
              `readOffset: ${readOffset}, writeOffset: ${writeOffset}, duration: ${duration}, audio.currentTime: ${audio.currentTime}, ac.currentTime: ${ac.currentTime}`
            );
            return await Promise.all([
              new Promise((resolve) => (stream.oninactive = resolve)),
              new Promise((resolve) => (ac.onstatechange = resolve)),
            ]);
          }
        }
        const { timestamp } = value;
        const int8 = new Int8Array(440);
        const sab = new Int8Array(memory.buffer);
        for (let i = 0; i < 440; i++) {
          int8[i] = sab[writeOffset];
          ++writeOffset;
        }
        const int16 = new Int16Array(int8.buffer);
        const floats = new Float32Array(220);
        // https://stackoverflow.com/a/35248852
        for (let i = 0; i < int16.length; i++) {
          const int = int16[i];
          // If the high bit is on, then it is a negative number, and actually counts backwards.
          const float =
            int >= 0x8000 ? -(0x10000 - int) / 0x8000 : int / 0x7fff;
          floats[i] = float;
        }
        const buffer = new AudioBuffer({
          numberOfChannels: 1,
          length: floats.length,
          sampleRate: 22050,
        });
        buffer.copyToChannel(floats, 0, 0);
        duration += buffer.duration;
        const frame = new AudioFrame({ timestamp, buffer });
        return audioWriter.write(frame).then(() => {
          return audioReader.read().then(process);
        });
      }),
    ]);
    transportStream.abortReading();
    await transportStream.readingAborted;
    transport.close();
    // recorder.stop();
    return transport.closed
      .then((_) => {
        console.log('WebTransport connection closed normally.');
        if ('gc' in globalThis) {
          globalThis.gc();
        }
        return 'Done streaming.';
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
