# Opt-in test image only; build dependency versions are recorded in the run log.
FROM ros:jazzy-ros-base@sha256:066420e07f60aa18262f2479981def87ebcfcec42eefb0c0c57c4a46098348ca
RUN apt-get update && apt-get install -y --no-install-recommends ros-jazzy-ros-gz git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /fixture
ENV PULPO_DISPOSABLE_SIMULATION=1 ROS_DOMAIN_ID=173 ROS_LOCALHOST_ONLY=1 GZ_IP=127.0.0.1
ENTRYPOINT ["/ros_entrypoint.sh", "python3", "scripts/test_simulation.py", "--backend", "gazebo"]
