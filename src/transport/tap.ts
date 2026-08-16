export interface Traffic {
  direction: "in" | "out";
  /** One complete JSON-RPC line, exactly as it crossed the wire. */
  line: string;
}

export type TrafficListener = (traffic: Traffic) => void;

function lineSplitter(onLine: (line: string) => void): {
  push: (chunk: Uint8Array) => void;
  flush: () => void;
} {
  const decoder = new TextDecoder();
  let buffered = "";

  return {
    push(chunk: Uint8Array): void {
      buffered += decoder.decode(chunk, { stream: true });
      for (let cut = buffered.indexOf("\n"); cut >= 0; cut = buffered.indexOf("\n")) {
        const line = buffered.slice(0, cut).trim();
        buffered = buffered.slice(cut + 1);
        if (line.length > 0) {
          onLine(line);
        }
      }
    },
    flush(): void {
      const line = buffered.trim();
      buffered = "";
      if (line.length > 0) {
        onLine(line);
      }
    },
  };
}

/**
 * Copies every line crossing the wire to a listener without touching what the
 * protocol sees. Wrapping the streams rather than the SDK keeps the transcript
 * honest: it records what was actually sent and received, not what we believe we
 * sent, and it cannot change either.
 */
export function tapStreams(
  stdin: WritableStream<Uint8Array>,
  stdout: ReadableStream<Uint8Array>,
  onTraffic: TrafficListener,
): { input: WritableStream<Uint8Array>; output: ReadableStream<Uint8Array> } {
  const outbound = lineSplitter((line) => {
    onTraffic({ direction: "out", line });
  });
  const inbound = lineSplitter((line) => {
    onTraffic({ direction: "in", line });
  });

  const writer = stdin.getWriter();
  const input = new WritableStream<Uint8Array>({
    async write(chunk) {
      outbound.push(chunk);
      await writer.write(chunk);
    },
    async close() {
      outbound.flush();
      await writer.close();
    },
    async abort(reason) {
      outbound.flush();
      await writer.abort(reason);
    },
  });

  const output = stdout.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        inbound.push(chunk);
        controller.enqueue(chunk);
      },
      flush() {
        inbound.flush();
      },
    }),
  );

  return { input, output };
}
