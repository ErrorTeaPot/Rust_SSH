mod widgets;
use crate::widgets::Input;
use rand::prelude::*;

fn main() {
    let mut rng = rand::thread_rng();
    for display_width in 3..10 {
        for _ in 0..1000 {
            let mut history = Vec::new();
            let mut input = Input {
                display_width,
                ..Default::default()
            };
            let chars = ['a', 'é', '字']; //, '𒈙'];
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for _ in 0..10_000 {
                    let r: u8 = rng.gen();
                    if r < 100 {
                        let c = chars[rng.gen::<usize>() % chars.len()];
                        history.push(c.to_string());
                        //println!("{}", c);
                        input.insert_at_cursor(c);
                    } else if r < 140 {
                        history.push("<-".to_string());
                        // println!("<-");
                        input.cursor_move_left();
                    } else if r < 180 {
                        history.push("->".to_string());
                        //println!("->");
                        input.cursor_move_right();
                    } else if r < 200 {
                        history.push("Del".to_string());
                        //println!("Bac<k");
                        input.delete_at_cursor();
                    } else {
                        history.push("Back".to_string());
                        //  println!("Del");
                        input.delete_behind_cursor();
                    }
                    history.push(format!(
                        "text: \"{}\", cursor_offset: {}, text_offset: {}",
                        input.text, input.cursor_offset, input.text_offset
                    ));
                }
            }));
            if res.is_err() {
                println!("{}", history.join("\n"));
                break;
            }
        }
    }
}
