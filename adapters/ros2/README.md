# ROS 2 adapter

The ROS 2 adapter binds Pulpo Autonomous permits into robot control and sensor orchestration flows.

This layer translates shared governance decisions into task execution, observation capture, and safety signaling within ROS 2 systems.

The current Python adapter is a translation stub. For the disposable ROS 2
Jazzy / Gazebo Harmonic test fixture, see the [simulation tester](../../docs/SIMULATION_TESTER.md).
It reports permit decisions, observed effects and bypass detection; it is not a
production robot executor or proof of actuator-path containment.
