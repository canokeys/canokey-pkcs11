use super::*;

#[derive(Default)]
struct Card {
    commands: Vec<Vec<u8>>,
    responses: std::collections::VecDeque<Result<Vec<u8>, u32>>,
}

unsafe extern "C" fn exchange(
    context: *mut c_void,
    command: *const u8,
    command_len: usize,
    response: *mut u8,
    response_len: *mut usize,
) -> u32 {
    let card = unsafe { &mut *context.cast::<Card>() };
    card.commands
        .push(unsafe { slice::from_raw_parts(command, command_len) }.to_vec());
    match card.responses.pop_front() {
        Some(Ok(bytes)) if bytes.len() <= unsafe { *response_len } => {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), response, bytes.len());
                *response_len = bytes.len();
            }
            0
        }
        Some(Err(status)) => status,
        _ => 1,
    }
}

fn command(data: &[u8]) -> Command {
    Command {
        header: [0, 0x87, 7, 0x9a],
        data: data.as_ptr(),
        data_len: data.len(),
        le: 256,
        chain: 1,
        get_response: 1,
    }
}

fn run(command: &Command, card: &mut Card, output: &mut [u8]) -> (u32, usize) {
    let mut len = output.len();
    let status = unsafe {
        cnk_protocol_run(
            command,
            Some(exchange),
            (card as *mut Card).cast(),
            output.as_mut_ptr(),
            &mut len,
        )
    };
    (status, len)
}

fn card(responses: &[&[u8]]) -> Card {
    Card {
        responses: responses.iter().map(|bytes| Ok(bytes.to_vec())).collect(),
        ..Default::default()
    }
}

#[test]
fn rsa_short_chaining_and_continuation_transcript() {
    let data = vec![0xa5; 266];
    let mut card = card(&[&[0x90, 0], &[1, 2, 0x61, 2], &[3, 4, 0x90, 0]]);
    let mut output = [0xa5; 8];
    assert_eq!(run(&command(&data), &mut card, &mut output), (OK, 6));
    assert_eq!(card.commands.len(), 3);
    let mut first = vec![0x10, 0x87, 7, 0x9a, 255];
    first.extend_from_slice(&data[..255]);
    let mut last = vec![0, 0x87, 7, 0x9a, 11];
    last.extend_from_slice(&data[255..]);
    last.push(0);
    assert_eq!(card.commands, vec![first, last, vec![0, 0xc0, 0, 0, 2]]);
    assert_eq!(output, [1, 2, 3, 4, 0x90, 0, 0xa5, 0xa5]);
}

#[test]
fn small_output_reports_complete_size_without_partial_copy() {
    let mut card = card(&[&[1, 2, 0x61, 2], &[3, 4, 0x90, 0]]);
    let mut output = [0xa5; 5];
    assert_eq!(run(&command(&[]), &mut card, &mut output), (SMALL, 6));
    assert_eq!(output, [0xa5; 5]);
    assert_eq!(card.commands.len(), 2);
}

#[test]
fn intermediate_failure_stops_before_final_mutation() {
    let data = vec![0xa5; 266];
    let mut card = card(&[&[0x69, 0x82]]);
    let mut output = [0xa5; 8];
    assert_eq!(run(&command(&data), &mut card, &mut output), (FAILED, 8));
    assert_eq!(card.commands.len(), 1);
    assert_eq!(output, [0xa5; 8]);
}

#[test]
fn final_authentication_status_is_preserved_without_retry() {
    for status in [[0x63, 0xc2], [0x6c, 8], [0x6a, 0x82]] {
        let mut card = card(&[&status]);
        let mut output = [0; 2];
        assert_eq!(run(&command(&[]), &mut card, &mut output), (OK, 2));
        assert_eq!(output, status);
        assert_eq!(card.commands.len(), 1);
    }
}

#[test]
fn no_continuation_when_disabled() {
    let mut request = command(&[]);
    request.get_response = 0;
    let mut card = card(&[&[1, 0x61, 0]]);
    let mut output = [0; 3];
    assert_eq!(run(&request, &mut card, &mut output), (OK, 3));
    assert_eq!(output, [1, 0x61, 0]);
    assert_eq!(card.commands.len(), 1);
}

#[test]
fn malformed_and_nonprogressing_responses_fail_atomically() {
    for responses in [vec![vec![0x90]], vec![vec![0x61, 1], vec![0x61, 1]]] {
        let mut card = Card {
            responses: responses.into_iter().map(Ok).collect(),
            ..Default::default()
        };
        let mut output = [0xa5; 8];
        assert_eq!(run(&command(&[]), &mut card, &mut output), (FAILED, 8));
        assert_eq!(output, [0xa5; 8]);
        assert!(card.commands.len() <= 2);
    }
}

#[test]
fn transport_failure_is_terminal_and_does_not_publish_prefix() {
    let mut card = Card {
        responses: [Ok(vec![1, 0x61, 1]), Err(42)].into(),
        ..Default::default()
    };
    let mut output = [0xa5; 8];
    assert_eq!(run(&command(&[]), &mut card, &mut output), (TRANSPORT, 8));
    assert_eq!(card.commands.len(), 2);
    assert_eq!(output, [0xa5; 8]);
}

#[test]
fn continuation_exchange_budget_terminates_progressing_card() {
    let mut card = Card {
        responses: (0..4100).map(|_| Ok(vec![1, 0x61, 1])).collect(),
        ..Default::default()
    };
    let mut output = [0xa5; 8];
    assert_eq!(run(&command(&[]), &mut card, &mut output), (FAILED, 8));
    assert_eq!(card.commands.len(), 4096);
    assert_eq!(output, [0xa5; 8]);
}

#[test]
fn invalid_descriptor_performs_no_io() {
    let mut request = command(&[]);
    request.data_len = BUDGET + 1;
    request.data = ptr::null();
    let mut card = Card::default();
    let mut output = [0xa5; 8];
    assert_eq!(run(&request, &mut card, &mut output), (ARGUMENT, 8));
    assert!(card.commands.is_empty());
}
