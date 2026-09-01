use pretty_assertions::assert_eq;

use super::SpawnAgentArgs;
use crate::agent::control::SpawnAgentForkMode;

fn args(fork_turns: Option<&str>) -> SpawnAgentArgs {
    SpawnAgentArgs {
        message: "bounded task".to_string(),
        task_name: "worker".to_string(),
        agent_type: None,
        model: None,
        reasoning_effort: None,
        fork_turns: fork_turns.map(str::to_string),
        fork_context: None,
    }
}

#[test]
fn fork_mode_requires_explicit_history_inheritance() {
    let cases = [
        (None, None),
        (Some("none"), None),
        (Some("all"), Some(SpawnAgentForkMode::FullHistory)),
        (Some("3"), Some(SpawnAgentForkMode::LastNTurns(3))),
    ];

    for (fork_turns, expected) in cases {
        assert_eq!(args(fork_turns).fork_mode().unwrap(), expected);
    }
}
