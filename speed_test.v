module vodcha

import time

fn test_quarter_round_is_fast_enough() {
    $if bench ? {
        sw := time.new_stopwatch(time.StopWatchOptions{})
        for _ in 0..1_000 { quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567) }
        delta := sw.elapsed().microseconds()
        println('took: $delta microseconds')
        assert delta < 1_000_000
    }
}