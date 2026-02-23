> On Tue, Mar 11, 2025 at 12:35 AM Reilly Grant reillyg@chromium.org wrote:
>
> That issue is obsolete. There is nothing stopping you from implementing a WebTransport server other than building an implementation using JavaScript or WebAssembly.
> Reilly Grant | Software Engineer | reillyg@chromium.org | Google Chrome
>
>
> On Mon, Mar 10, 2025 at 5:22 PM guest271314 guest271314@gmail.com wrote:
>>
>> The goal with HTTPS/TLS being able to create a WebTransport server
>> with TCPSeverSocket, for full-duplex streaming using WHATWG Streams.
>>
>>
>> On Mon, Mar 10, 2025 at 11:53 PM Reilly Grant reillyg@chromium.org wrote:
>> >
>> > There's nothing stopping you from implementing your own TLS client/server library on top of the Direct Sockets API. The API proposed here makes that easier by allowing you to validate certificates using the browser's certificate store instead of providing your own.
>> > Reilly Grant | Software Engineer | reillyg@chromium.org | Google Chrome
>> >
