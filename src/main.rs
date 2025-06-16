use std::time::Instant;
use sysinfo::{System};
use std::fs;

use crate::{prover::prover_calculate, verifier::{verifier_prove, verifier_set_up}};
mod addon;
mod prover;
mod verifier;


fn main() {
    let mut verifier_set_up_stat: Vec<(f32, f32, f32)> = vec![];     // step 1: verifier sets up params, encrypts, signs
    let mut prover_stat: Vec<(f32, f32, f32)> = vec![];     // step 2: prover verifies sig, computes result
    let mut verifier_verify_stat: Vec<(f32, f32, f32)> = vec![];     // step 3: verifier proves the result
    let mut csv_string: String = "run, verifierSetUpCPU, verifierSetUpMemory, verifierSetUpTime, proverCPU, proverMemory, proverTime, verifierVerifyCPU, verifierVerifyMemory, verifierVerifyTime\n".to_owned();

    for i in 0..400 {
        println!("Run: {}", i+1);
        let pid = sysinfo::get_current_pid().expect("Couldn't get current PID");
        let mut system = System::new_all();
        let degree_threshold_timestamp = 1262304000;  // Unix timestamp: Fri Jan 01 2010 00:00:00
        let degree_issuance_timestamp = 1500000000;   // Unix timestamp: Fri Jul 14 2017 02:40:00
        let now = Instant::now();
        let (verifying_key, signature, threshold_ciphertext_ser, encryptor, decryptor, evaluator) = verifier_set_up(degree_threshold_timestamp);
        let elapsed = now.elapsed();
        let elapsed_f32 = elapsed.as_secs_f32() * 1000f32;
        system.refresh_processes(); 
        if let Some(process) = system.process(pid) {
            let memory_f32 = process.memory() as f32 / 1024f32 /1024f32;
            verifier_set_up_stat.push((process.cpu_usage(), memory_f32, elapsed_f32));
        } else {
            println!("Process not found!");
        }

        let now = Instant::now();
        let calculation_result = prover_calculate(degree_issuance_timestamp, verifying_key, signature, threshold_ciphertext_ser, encryptor, evaluator);
        let elapsed = now.elapsed();
        let elapsed_f32 = elapsed.as_secs_f32() * 1000f32;
        system.refresh_processes();
        if let Some(process) = system.process(pid) {
            let memory_f32 = process.memory() as f32 / 1024f32 /1024f32;
            prover_stat.push((process.cpu_usage(), memory_f32, elapsed_f32));
        } else {
            println!("Process not found!");
        }

        let now = Instant::now();
        let result = verifier_prove(calculation_result, decryptor);
        let elapsed = now.elapsed();
        let elapsed_f32 = elapsed.as_secs_f32() * 1000f32;
        system.refresh_processes();
        if let Some(process) = system.process(pid) {
            let memory_f32 = process.memory() as f32 / 1024f32 /1024f32;
            verifier_verify_stat.push((process.cpu_usage(), memory_f32, elapsed_f32));
        } else {
            println!("Process not found!");
        }
        let str = format!("{:?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}, {:.2?}\n", i+1, verifier_set_up_stat[i].0, verifier_set_up_stat[i].1, verifier_set_up_stat[i].2, prover_stat[i].0, prover_stat[i].1, prover_stat[i].2, verifier_verify_stat[i].0, verifier_verify_stat[i].1, verifier_verify_stat[i].2);
        csv_string.push_str(&str);
    }
    fs::write("HE_rs_performance_data.csv", csv_string).expect("Unable to write file");
}

