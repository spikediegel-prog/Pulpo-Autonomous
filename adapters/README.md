# Adapters

Adapters translate shared Pulpo Autonomous authority into execution-specific interfaces without creating a second authority source.

Adapter layers may integrate:

- simulation environments
- ROS 2 systems
- MAVLink or telemetry stacks
- vehicle control stacks
- spacecraft command and telemetry interfaces

Camera, OCR, QR, and vision-model adapters are untrusted observation sources.
Use `adapters.vision.UntrustedVisionBoundary` as a proposal-only boundary,
then require an existing canonical permit, shared safety gates, and local
controller interlocks before execution.

Microphone, speech, audible-tone, ultrasonic, and subsonic audio adapters are
also untrusted. Use `adapters.audio.UntrustedAudioBoundary`; audio may propose
but never authorize or execute an action.
