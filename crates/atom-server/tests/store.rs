use atom_ledger::HmacSha256Signer;
use atom_server::store::Store;

fn test_signer() -> Box<dyn atom_ledger::CheckpointSigner> {
    Box::new(HmacSha256Signer::new(
        "test",
        b"00000000000000000000000000000000",
    ))
}

#[test]
fn store_appends_and_lists_mission() {
    let mut store = Store::open_in_memory(test_signer()).unwrap();
    let mission = serde_json::json!({
        "mission_id": "m-1",
        "state": "CREATED",
        "goal": "compare atom vs hermes",
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z",
    });
    store.append_mission_created(&mission).unwrap();
    let all = store.missions();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["mission_id"], "m-1");
    assert_eq!(all[0]["state"], "CREATED");
}

#[test]
fn store_persists_effect_observation_secret() {
    let mut store = Store::open_in_memory(test_signer()).unwrap();
    store
        .append_effect(&serde_json::json!({"effect_id": "e-1", "state": "DISPATCHED"}))
        .unwrap();
    store
        .add_observation(&serde_json::json!({"observation_id": "o-1", "claim_id": "c-1"}))
        .unwrap();
    store
        .add_secret_handle(&serde_json::json!({"handle_id": "h-1", "name": "creds"}))
        .unwrap();
    assert_eq!(store.effects().len(), 1);
    assert_eq!(store.observations().len(), 1);
    assert_eq!(store.secret_handles().len(), 1);
    assert_eq!(store.effects()[0]["state"], "DISPATCHED");
}

#[test]
fn store_update_mission() {
    let mut store = Store::open_in_memory(test_signer()).unwrap();
    let created = serde_json::json!({
        "mission_id": "m-2",
        "state": "CREATED",
        "goal": "g",
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z",
    });
    store.append_mission_created(&created).unwrap();
    let updated = serde_json::json!({
        "mission_id": "m-2",
        "state": "CANCELLED",
        "goal": "g",
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T01:00:00Z",
    });
    store.update_mission("m-2", &updated).unwrap();
    assert_eq!(store.missions()[0]["state"], "CANCELLED");
}
