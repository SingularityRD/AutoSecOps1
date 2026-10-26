"""RoboDR trusted rule catalog (`robodr_ocsf::builder`), as data.

Generated from `crates/robodr-ocsf/src/builder.rs` through
`rule_info_for_contract` for contract 2.0.0 and 2.1.0. Do not edit by hand:
`tests/registry/test_robodr.py::test_python_catalog_matches_rust_source`
compares it with the Rust source when that source is available
(`ROBODR_SOURCE_DIR`).
"""

from typing import NamedTuple


class RuleInfo(NamedTuple):
    title: str
    desc: str
    data_source: str
    techniques: tuple[tuple[str, str], ...]


GENERIC = RuleInfo(
    "RoboDR model-profile deviation",
    "The detection core reported a deviation from the locked model profile for a rule without a catalog entry.",
    "robodr",
    (),
)
"""Entry for a rule id without a catalog entry."""

CORRELATE_GENERIC = RuleInfo(
    "Correlated RoboDR detection",
    "A deployment-specific correlation rule combined several detections that were each reported on their own; the correlation cites every contributing detection.",
    "robodr_correlation",
    (),
)
"""Entry for a `robot.correlate.*` id without its own entry."""

CATALOG_BASE: dict[str, RuleInfo] = {
    "robot.agent.control_plane_invalid": RuleInfo(
        "Invalid control-plane action request refused",
        "The robot's control-plane API refused authenticated requests for an action, parameter, time limit or authority it never allows; each was recorded in the black box and nothing was executed.",
        "robodr_agent",
        (),
    ),
    "robot.agent.control_plane_unauthenticated": RuleInfo(
        "Control-plane request failed authentication",
        "The robot's control-plane API refused requests that did not carry a valid SOC signature (missing or bad signature, unknown key, stale timestamp or replayed nonce); nothing was judged or executed.",
        "robodr_agent",
        (),
    ),
    "robot.agent.correlation_pressure": RuleInfo(
        "Correlation engine state under pressure",
        "The correlation engine evicted or refused pending correlation state, which happens when many fresh entities arrive within a window (possibly a flood aimed at hiding a correlation).",
        "robodr_agent",
        (),
    ),
    "robot.agent.evidence_degraded": RuleInfo(
        "Black-box recording failing",
        "The black-box recorder failed to store evidence; records from this outage are missing.",
        "robodr_agent",
        (),
    ),
    "robot.agent.evidence_quarantined": RuleInfo(
        "Damaged black-box segment quarantined",
        "Opening the black box found closed segments that failed verification; they were copied to quarantine and recording continued without reusing sequence numbers.",
        "robodr_agent",
        (),
    ),
    "robot.agent.evidence_truncated": RuleInfo(
        "Black-box records cut after the newest mark",
        "Opening the black box found authentic proof that records after its newest integrity mark were removed; treat the evidence store as tampered with.",
        "robodr_agent",
        (),
    ),
    "robot.agent.input_ended": RuleInfo(
        "Agent input ended",
        "An agent input reached end of stream or failed while the daemon was running; detections from that input stopped.",
        "robodr_agent",
        (),
    ),
    "robot.agent.input_malformed": RuleInfo(
        "Malformed agent input",
        "An agent input delivered items that could not be parsed; they were skipped.",
        "robodr_agent",
        (),
    ),
    "robot.agent.input_silent": RuleInfo(
        "Agent input silent",
        "An agent input delivered no valid data within the silence window; the robot state reads unknown while the agent is blind.",
        "robodr_agent",
        (),
    ),
    "robot.agent.pipeline_lag": RuleInfo(
        "Agent pipeline lagging",
        "Queue latency or tick delay in the agent exceeded the configured lag bound; detections are late.",
        "robodr_agent",
        (),
    ),
    "robot.agent.queue_overflow": RuleInfo(
        "Agent input queue overflowed",
        "The agent's input queue was full and items were dropped without inspection.",
        "robodr_agent",
        (),
    ),
    "robot.agent.spool_full": RuleInfo(
        "Finding spool full or failing",
        "The agent could not write findings to its outbound spool (full or write errors); findings may be lost before export.",
        "robodr_agent",
        (),
    ),
    "robot.capture.bad_checksum": RuleInfo(
        "IP or UDP checksum failures",
        "Captured packets failed the IPv4 header or UDP checksum; the robot's kernel drops these too (injection attempt aimed at the sensor, or a faulty interface).",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.ip_fragment_conflict": RuleInfo(
        "Conflicting overlapping IP fragments",
        "IP fragments overlapped with conflicting bytes, an evasion pattern; the host may reassemble different content than the sensor inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.ip_fragment_duplicate_conflict": RuleInfo(
        "Duplicate IP fragment with different content",
        "A duplicate IP fragment differed from the queued copy (first copy kept); what was inspected may differ from what the host accepts.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.ip_fragment_refused": RuleInfo(
        "IP fragments refused, reassembly budget full",
        "IP fragments were refused because the reassembly budget was full; those datagrams were not inspected (possibly a flood aimed at blinding the sensor).",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.ip_reassembly_dropped": RuleInfo(
        "IP datagrams dropped in reassembly",
        "IP datagrams were dropped for bad fragment geometry or reassembly timeout; they were not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.ip_reassembly_evicted": RuleInfo(
        "IP datagrams evicted from reassembly",
        "Partially reassembled IP datagrams were evicted to bound memory; they were not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.malformed_frames": RuleInfo(
        "Malformed or truncated captured frames",
        "The capture saw malformed or truncated frames; they were not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.not_udp": RuleInfo(
        "Non-UDP packets reached the sensor",
        "IP packets that were not UDP passed the kernel capture filter; they were not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.capture.unsupported_middleware": RuleInfo(
        "Robot middleware not inspected (Zenoh)",
        "The capture sees Zenoh (rmw_zenoh) traffic, which RoboDR does not decode: participants, publishers and motion commands on it are not inspected; with no RTPS at all the sensor is blind to the robot's bus.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.correlate.coordinated_intrusion": RuleInfo(
        "Correlated intrusion: unknown participant, foreign motion writer and host anomaly",
        "Within one minute an unknown DDS participant, an unauthorized motion writer and a host process anomaly were each detected; the correlation cites every contributing detection.",
        "robodr_correlation",
        (("T0848", "Rogue Master"), ("T0855", "Unauthorized Command Message")),
    ),
    "robot.correlate.correlation_state_evicted": RuleInfo(
        "Correlation evidence evicted under pressure",
        "The correlation engine evicted a pending group that already held evidence to stay within its bounds; the named correlation rule may have missed a detection. Observe-only.",
        "robodr_correlation",
        (),
    ),
    "robot.correlate.credential_theft": RuleInfo(
        "Correlated credential theft: SROS 2 key read, then a foreign participant",
        "An SROS 2 private key was read outside the ROS stack and an unknown or source-mismatched participant appeared afterwards within the correlation window.",
        "robodr_correlation",
        (("T0848", "Rogue Master"),),
    ),
    "robot.correlate.defense_tampering": RuleInfo(
        "Correlated defense tampering: protected file or service change with a silent input",
        "A host rule saw a RoboDR or Pulsar protected file change or a service stop while the agent reported an input silent or ended; observe-only by construction.",
        "robodr_correlation",
        (),
    ),
    "robot.correlate.discovery_flood": RuleInfo(
        "Correlated discovery flood: unknown participants from many addresses",
        "Unknown DDS participants were announced from many distinct source addresses within the correlation window: a discovery flood or scan.",
        "robodr_correlation",
        (("T0848", "Rogue Master"),),
    ),
    "robot.correlate.host_process_persistence": RuleInfo(
        "Correlated host activity: one process tripped several host rules",
        "The same host process raised several host-side detections within the correlation window.",
        "robodr_correlation",
        (),
    ),
    "robot.correlate.motion_hijack": RuleInfo(
        "Correlated motion hijack: foreign motion source, then unexpected motion",
        "A foreign motion writer or a firewall source rejection was followed by uncommanded motion, feedback divergence or a second feedback publisher within the correlation window.",
        "robodr_correlation",
        (
            ("T0855", "Unauthorized Command Message"),
            ("T0831", "Manipulation of Control"),
        ),
    ),
    "robot.correlate.sensor_evasion": RuleInfo(
        "Correlated sensor evasion: capture refusals with uninspected discovery",
        "Repeated capture or fragment refusals coincided with discovery traffic the sensor could not inspect, a pattern consistent with an attempt to blind the sensor.",
        "robodr_correlation",
        (),
    ),
    "robot.correlate.spoofed_motion_source": RuleInfo(
        "Correlated spoofed motion source from one address",
        "A participant or endpoint source mismatch was followed by an unauthorized motion writer from the same source address within the correlation window.",
        "robodr_correlation",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.correlate.trojaned_package_key_access": RuleInfo(
        "Correlated supply-chain compromise: package install, then key access",
        "A package install or maintainer script was followed by an SROS 2 private key read within the correlation window.",
        "robodr_correlation",
        (),
    ),
    "robot.dds.unknown_raw_writer": RuleInfo(
        "Writer on a raw DDS topic outside the model profile",
        "A writer was announced on a non-ROS DDS topic the locked model profile does not allow.",
        "ros2_dds_discovery",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.firewall.events_dropped": RuleInfo(
        "Motion firewall events dropped",
        "The motion firewall's event buffer was full and events were dropped or evicted; this finding is as severe as the worst event lost.",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.internal_fault": RuleInfo(
        "Motion firewall internal fault",
        "The motion firewall failed its own post-condition check and applied its configured fault policy to the command.",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.limited_acceleration": RuleInfo(
        "Motion command acceleration limited",
        "The motion firewall limited a command's acceleration to the channel's bound (in observe mode: would have limited).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.limited_jerk": RuleInfo(
        "Motion command jerk limited",
        "The motion firewall limited a command's jerk to the channel's bound (in observe mode: would have limited).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.limited_speed": RuleInfo(
        "Motion command speed limited",
        "The motion firewall limited a command's speed to the channel's bound (in observe mode: would have limited).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_clock_regression": RuleInfo(
        "Motion command rejected: clock regression",
        "The motion firewall rejected a command because the gateway clock went backwards (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_future_timestamp": RuleInfo(
        "Motion command rejected: future timestamp",
        "The motion firewall rejected a command stamped in the future (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_kind_mismatch": RuleInfo(
        "Motion command rejected: kind mismatch",
        "The motion firewall rejected a command whose kind (twist or joints, joint count) does not match the channel (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_non_finite": RuleInfo(
        "Motion command rejected: non-finite value",
        "The motion firewall rejected a command carrying NaN or infinity (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.rejected_out_of_order": RuleInfo(
        "Motion command rejected: out of order",
        "The motion firewall rejected a command stamped no later than the previous one from the same source on the channel, a replay or reordering (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_over_hard_limit": RuleInfo(
        "Motion command rejected: over hard limit",
        "The motion firewall rejected a command whose speed exceeded the channel's hard-reject bound (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.rejected_rate_limited": RuleInfo(
        "Motion command rejected: rate limit",
        "The motion firewall rejected a command over the channel's rate limit (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_stale": RuleInfo(
        "Motion command rejected: stale",
        "The motion firewall rejected a command older than its freshness bound (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.rejected_unauthorized_source": RuleInfo(
        "Motion command rejected: unauthorised source",
        "The motion firewall rejected a command from a source not authorised on the channel (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.firewall.rejected_unknown_channel": RuleInfo(
        "Motion command rejected: unknown channel",
        "The motion firewall rejected a command on a channel its policy does not know (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.firewall.rejected_unknown_source": RuleInfo(
        "Motion command rejected: unknown source",
        "The motion firewall rejected a command from a source its policy does not know (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.host.pulsar_threat": RuleInfo(
        "Host runtime-security detection (Pulsar rule)",
        "A Pulsar runtime-security rule fired on the robot controller (process, file or network activity of the host operating system); the detail names the Pulsar rule and the process.",
        "host_runtime",
        (),
    ),
    "robot.motion.angular_over_envelope": RuleInfo(
        "Roll/pitch rate command exceeds the motion envelope",
        "A commanded roll/pitch rate exceeded the maximum allowed by the locked model profile for this channel.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.cross_sensor_disagreement": RuleInfo(
        "Independent motion sensors disagree",
        "Two independent feedback sources persistently disagreed about the platform's motion.",
        "ros2_motion_commands",
        (("T0856", "Spoof Reporting Message"),),
    ),
    "robot.motion.decode_anomaly": RuleInfo(
        "Motion sample decode anomaly",
        "A decoded motion or feedback sample carried an oddity that did not stop decoding, such as trailing bytes.",
        "ros2_motion_commands",
        (),
    ),
    "robot.motion.feedback_divergence": RuleInfo(
        "Motion feedback diverges from commands",
        "Measured feedback stayed apart from what the observed commands predict for longer than the configured tolerance.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.frozen_feedback": RuleInfo(
        "Motion feedback frozen or silent",
        "Motion feedback was frozen, silent or carried anomalous timestamps; the platform's motion cannot be verified.",
        "ros2_motion_commands",
        (),
    ),
    "robot.motion.inconsistent_feedback_stream": RuleInfo(
        "Inconsistent motion feedback stream",
        "One feedback stream repeatedly jumped between values faster than the platform can accelerate: interleaved publishers under one identity, or a faulty driver.",
        "ros2_motion_commands",
        (("T0856", "Spoof Reporting Message"),),
    ),
    "robot.motion.invalid_feedback": RuleInfo(
        "Motion feedback with a non-finite value",
        "Motion feedback carried NaN or infinity.",
        "ros2_motion_commands",
        (),
    ),
    "robot.motion.joint_over_envelope": RuleInfo(
        "Joint speed command exceeds the motion envelope",
        "A commanded joint speed exceeded the maximum allowed by the locked model profile for this channel.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.linear_over_envelope": RuleInfo(
        "Linear speed command exceeds the motion envelope",
        "A commanded linear speed (forward, lateral, vertical or their resultant) exceeded the maximum allowed by the locked model profile for this channel.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.multiple_feedback_publishers": RuleInfo(
        "Several publishers for one feedback source",
        "More than one publisher interleaved samples for the same feedback source type.",
        "ros2_motion_commands",
        (("T0856", "Spoof Reporting Message"),),
    ),
    "robot.motion.non_finite_command": RuleInfo(
        "Motion command with a non-finite value",
        "A motion command carried NaN or infinity on at least one axis; no envelope can bound it.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.sample_source_mismatch": RuleInfo(
        "Motion sample from an address not bound to its writer",
        "A decoded motion or feedback sample came from a source address not bound to its writer's participant.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.motion.unattributed_sample": RuleInfo(
        "Motion sample from an unattributed writer",
        "A motion or feedback sample came from a writer that was never announced, or whose binding is unbound or contested; it was not treated as authorised.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.motion.uncommanded_motion": RuleInfo(
        "Uncommanded motion",
        "Feedback measured motion while the observed command was rest or absent.",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.undecodable_sample": RuleInfo(
        "Undecodable motion or feedback sample",
        "A sample on a motion or feedback topic could not be decoded; it was not inspected.",
        "ros2_motion_commands",
        (),
    ),
    "robot.motion.unprofiled_channel": RuleInfo(
        "Motion command on an unprofiled channel",
        "A motion command was observed on a channel that has no envelope in the locked model profile.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.motion.unverifiable_command": RuleInfo(
        "Motion command that cannot be bounded",
        "A decoded command's speed cannot be bounded from the message, so no envelope can check it.",
        "ros2_motion_commands",
        (),
    ),
    "robot.profile.invalid_envelope": RuleInfo(
        "Motion envelope in the profile cannot be enforced",
        "The profile's envelope for this channel has an invalid or missing mandatory limit; every command on the channel is reported (fail closed).",
        "ros2_motion_commands",
        (),
    ),
    "robot.ros2.ambiguous_discovery": RuleInfo(
        "Ambiguous discovery announcement",
        "A discovery announcement repeats an identity parameter with conflicting values; DDS stacks differ on which one wins, so what was inspected may not be what a stack acts on.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.ros2.endpoint_source_mismatch": RuleInfo(
        "DDS endpoint announced from an unbound address",
        "An endpoint announcement for a participant came from an address not bound to it, or was relayed or GUID-conflicting from an untrusted address.",
        "ros2_dds_discovery",
        (("T0848", "Rogue Master"),),
    ),
    "robot.ros2.endpoint_unannounced_participant": RuleInfo(
        "DDS endpoint for a participant that never announced itself",
        "An endpoint announcement referred to a participant with no participant announcement within the hold window, or the hold queue overflowed.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.ros2.identity_instances_exceeded": RuleInfo(
        "Extra DDS participant claims a robot identity",
        "A participant matched a stable identity of the profile (source IP, DDS vendor, enclave) whose allowed instances are all held by live participants; it is not trusted.",
        "ros2_dds_discovery",
        (("T0848", "Rogue Master"),),
    ),
    "robot.ros2.participant_removed": RuleInfo(
        "Profiled DDS participant removed",
        "A participant in the locked model profile was announced as disposed or unregistered.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.ros2.participant_source_mismatch": RuleInfo(
        "DDS participant announced from an unbound address",
        "A participant announcement for a bound participant came from an address outside its binding, or was relayed by an untrusted address; it was not learned.",
        "ros2_dds_discovery",
        (("T0848", "Rogue Master"),),
    ),
    "robot.ros2.profile_refused": RuleInfo(
        "Model profile refused",
        "The model profile failed validation and is not enforced; the sensor reports in observe-only mode.",
        "robodr_agent",
        (),
    ),
    "robot.ros2.profile_state_tampered": RuleInfo(
        "Profile anti-rollback state missing or behind the black box",
        "The profile anti-rollback state file is missing or older than the newest accepted-profile record in the black box; the black-box record was used as the baseline.",
        "robodr_agent",
        (),
    ),
    "robot.ros2.unauthorized_motion_writer": RuleInfo(
        "Unauthorized publisher on a motion topic",
        "A participant that is not in the locked model profile announced a writer on a motion/control topic.",
        "ros2_dds_discovery",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.ros2.unknown_action": RuleInfo(
        "Writer on an action outside the model profile",
        "A writer was announced on a ROS 2 action topic or service the locked model profile does not allow.",
        "ros2_dds_discovery",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.ros2.unknown_participant": RuleInfo(
        "Unknown DDS participant joined the robot graph",
        "A DDS participant that is not in the locked model profile announced itself on the robot's RTPS discovery bus.",
        "ros2_dds_discovery",
        (("T0848", "Rogue Master"),),
    ),
    "robot.ros2.unknown_reader": RuleInfo(
        "Unknown subscriber in the robot graph",
        "A participant that is not in the locked model profile announced a reader; it cannot command but may collect data.",
        "ros2_dds_discovery",
        (("T0801", "Monitor Process State"),),
    ),
    "robot.ros2.unknown_reader_topic": RuleInfo(
        "Subscriber on a topic outside the reader allowlist",
        "A reader was announced on a topic, service or action outside the profile's reader allowlist; it cannot command but may collect data.",
        "ros2_dds_discovery",
        (("T0801", "Monitor Process State"),),
    ),
    "robot.ros2.unknown_service": RuleInfo(
        "Writer on a service outside the model profile",
        "A writer was announced on a ROS 2 service request or reply the locked model profile does not allow.",
        "ros2_dds_discovery",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.ros2.unknown_writer_topic": RuleInfo(
        "Writer on a topic outside the model profile",
        "A writer was announced on a topic the locked model profile does not allow anyone to publish to.",
        "ros2_dds_discovery",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.rtps.discovery_fragment_conflict": RuleInfo(
        "Conflicting discovery fragments",
        "Discovery fragments overlapped already received bytes with different content; a DDS stack may act on a different announcement than the one inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.discovery_fragment_evicted": RuleInfo(
        "Partial discovery samples evicted",
        "Partially reassembled discovery samples were evicted to stay within the reassembler's bounds; those announcements were not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.discovery_fragment_rejected": RuleInfo(
        "Discovery fragments refused",
        "Discovery fragments were refused (over a cap, bad geometry or no capacity); that announcement was not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.discovery_not_inspected": RuleInfo(
        "Discovery traffic not inspected",
        "The parser had to drop all or part of a discovery datagram (unsupported version, malformed parameter list, undecodable name); that content was not inspected.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.discovery_removal": RuleInfo(
        "Discovery dispose or unregister",
        "A discovery dispose or unregister arrived for an entity other than a profiled participant.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.fragmented_discovery": RuleInfo(
        "Fragmented RTPS discovery data",
        "Discovery data arrived fragmented (DATA_FRAG) and was reassembled before inspection.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.rtps.malformed_discovery": RuleInfo(
        "Malformed RTPS discovery traffic",
        "The RTPS parser saw discovery content a well-behaved DDS stack would not send.",
        "ros2_dds_discovery",
        (),
    ),
    "robot.safety_state.undecodable_sample": RuleInfo(
        "Undecodable safety-state sample",
        "A safety-state sample from a trusted writer could not be decoded; that source reads unknown until a valid sample arrives.",
        "robot_safety_state",
        (),
    ),
    "robot.safety_state.unmapped_value": RuleInfo(
        "Safety-state value outside the configured mapping",
        "A trusted safety-state source carried a value the configured mapping does not cover; that source reads unknown.",
        "robot_safety_state",
        (),
    ),
    "robot.safety_state.untrusted_source": RuleInfo(
        "Safety-state sample from an untrusted writer",
        "A safety-state sample came from a writer the locked model profile does not vouch for; it was ignored and the safety state was not taken from it.",
        "robot_safety_state",
        (("T0856", "Spoof Reporting Message"),),
    ),
    "robot.safety_state.writer_overflow": RuleInfo(
        "Safety-state writer table overflowed",
        "A safety-state source saw more fresh writers or socket connections than it keeps; that source reads at least unknown until the extra writers go stale.",
        "robot_safety_state",
        (),
    ),
    "robot.sensor.findings_capped": RuleInfo(
        "Sensor findings capped for one input",
        "One input produced more findings than the per-datagram cap; the least severe were suppressed.",
        "ros2_dds_discovery",
        (),
    ),
}
"""Contract 1.0 entries plus the 1.3 entries: the catalog of 2.0."""

CATALOG_2_1: dict[str, RuleInfo] = {
    "robot.firewall.crc_invalid": RuleInfo(
        "Joint command integrity check failed",
        "A low-level joint command arrived with an invalid frame checksum, or unchecked where the channel requires one; the motion firewall rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.firewall.disabled_motor_energised": RuleInfo(
        "Disabled motor energised",
        "A low-level joint command energises a motor slot the profile marks as unused (non-zero torque or gain); the motion firewall rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (
            ("T0831", "Manipulation of Control"),
            ("T0855", "Unauthorized Command Message"),
        ),
    ),
    "robot.firewall.joint_gain_below_minimum": RuleInfo(
        "Joint command gain below minimum",
        "The motion firewall rejected a low-level joint command whose stiffness or damping gain is below the joint's minimum (a disabled motor counts as zero gains); gains are never raised (in observe mode: would have rejected).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_gain_out_of_envelope": RuleInfo(
        "Joint command gain out of envelope",
        "The motion firewall found a low-level joint command whose stiffness or damping gain lies outside the joint's range; gains are only ever lowered, a gain below its minimum is rejected (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_hold_exceeded": RuleInfo(
        "Humanoid joint hold exceeded its time limit",
        "The motion firewall has been holding a humanoid's last valid joint frame for longer than the configured hold time because newer frames keep being rejected; it keeps holding with the feed-forward torque removed and needs escalation.",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.joint_limp_frame": RuleInfo(
        "Humanoid joint command would go limp",
        "A low-level joint command for a humanoid leaves every enabled joint without stiffness or damping, which makes the robot fall; the motion firewall rejected it and held the last valid frame (in observe mode: would have).",
        "ros2_motion_commands",
        (
            ("T0831", "Manipulation of Control"),
            ("T0855", "Unauthorized Command Message"),
        ),
    ),
    "robot.firewall.joint_mode_inconsistent": RuleInfo(
        "Joint command mode inconsistent",
        "A low-level joint command switches a motor off while carrying non-zero gains or torque for it; the motion firewall rejected it rather than forward unchecked values (in observe mode: would have).",
        "ros2_motion_commands",
        (
            ("T0831", "Manipulation of Control"),
            ("T0855", "Unauthorized Command Message"),
        ),
    ),
    "robot.firewall.joint_mode_pin_mismatch": RuleInfo(
        "Joint command operating mode changed",
        "A low-level joint command carries a frame-level mode (ankle control mode or robot variant) other than the one the channel is pinned to, which changes what the joint envelope means; the motion firewall rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (
            ("T0831", "Manipulation of Control"),
            ("T0855", "Unauthorized Command Message"),
        ),
    ),
    "robot.firewall.joint_pd_torque_out_of_envelope": RuleInfo(
        "Joint command proportional torque out of envelope",
        "The motion firewall found a low-level joint command whose stiffness times position step exceeds the joint's proportional torque bound and stepped or rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_position_out_of_envelope": RuleInfo(
        "Joint command position out of envelope",
        "The motion firewall found a low-level joint command whose position target lies outside the joint's envelope and clamped or rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_rate_violation": RuleInfo(
        "Joint command stream gap",
        "The gap between two low-level joint commands on a channel exceeded its configured maximum interval; recorded only, the late frame is still decided normally.",
        "ros2_motion_commands",
        (),
    ),
    "robot.firewall.joint_step_out_of_envelope": RuleInfo(
        "Joint command position step out of envelope",
        "The motion firewall found a low-level joint command whose position target moved further from the previous accepted target than the joint's per-frame step bound and stepped or rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_torque_out_of_envelope": RuleInfo(
        "Joint command torque out of envelope",
        "The motion firewall found a low-level joint command whose feed-forward torque exceeds the joint's bound and clamped or rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.firewall.joint_velocity_out_of_envelope": RuleInfo(
        "Joint command velocity out of envelope",
        "The motion firewall found a low-level joint command whose velocity target exceeds the joint's bound and clamped or rejected it (in observe mode: would have).",
        "ros2_motion_commands",
        (("T0831", "Manipulation of Control"),),
    ),
    "robot.motion.api_id_out_of_range": RuleInfo(
        "Robot API request with an aliased call id",
        "A robot API request carried a call id outside the 32-bit range the robot dispatches on, so the robot executes a different call than the one written.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.motion.command_type_mismatch": RuleInfo(
        "Motion command writer with an unexpected type",
        "A writer on a profiled motion command channel announced a type name other than the one the locked profile records for the channel, a type no decoder knows, or a feedback type: its commands cannot be checked as the profile intends.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.motion.control_handover": RuleInfo(
        "Motor control handed to another channel",
        "A command hands motor control to, or takes it from, another channel or controller (motion switcher release, user or arm SDK control).",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.ros2.discovery_flood": RuleInfo(
        "Discovery flood: unknown participants aggregated",
        "One source address (or many) announced more new DDS participants than are reported one by one; their per-participant findings are folded into this one, with the count per rule, first and last seen and sample GUID prefixes, and each is still recorded in the black box. A GUID spray or a discovery scan, possibly aimed at flooding the findings path.",
        "ros2_dds_discovery",
        (("T0848", "Rogue Master"),),
    ),
    "robot.unitree.legacy_port_rtps": RuleInfo(
        "RTPS traffic on a Unitree legacy UDP port",
        "A datagram on a configured Unitree legacy UDP port also parses as RTPS; it was inspected on both paths. DDS traffic on the legacy command ports is not normal and can be an attempt to evade the legacy sender check.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.unitree.legacy_sender_flood": RuleInfo(
        "Unitree legacy UDP frames from many unknown hosts",
        "Unitree legacy (unitree_legged_sdk) UDP frames arrived from more unlisted source addresses than are reported one by one, or listed command senders appeared with many different wrong link-layer addresses; the frames are counted in aggregate. A spoofed-source flood or a scan of the robot's command ports.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.unitree.legacy_sender_mac_mismatch": RuleInfo(
        "Unitree legacy command from a listed IP with the wrong MAC",
        "A Unitree legacy UDP command came from a configured command sender IP, but its link-layer source address is not the MAC bound to that IP (or could not be verified because the datagram was reassembled from fragments): another host on the LAN may be using the sender's address.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
    "robot.unitree.legacy_unknown_sender": RuleInfo(
        "Unitree legacy UDP frame from an unknown host",
        "A Unitree legacy (unitree_legged_sdk, Go1 generation) UDP command or state frame came from a source address the sensor configuration does not list; the protocol is unauthenticated, so an unlisted command sender can drive the robot.",
        "ros2_motion_commands",
        (("T0855", "Unauthorized Command Message"),),
    ),
}
"""Entries added in contract 2.1 (`catalog_2_1`)."""

CATALOG_2_1_MINOR = 1


def rule_info_for_contract(rule_id: str, major: int, minor: int) -> RuleInfo:
    """The catalog entry a 2.x message of this minor must carry for `rule_id`."""
    if major != 2:
        raise ValueError("only robodr.findings 2.x is supported")
    if (info := CATALOG_BASE.get(rule_id)) is not None:
        return info
    if rule_id.startswith("robot.correlate."):
        return CORRELATE_GENERIC
    if minor >= CATALOG_2_1_MINOR and (info := CATALOG_2_1.get(rule_id)) is not None:
        return info
    return GENERIC
