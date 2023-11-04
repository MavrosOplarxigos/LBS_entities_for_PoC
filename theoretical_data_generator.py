import sys

EXPERIMENT_START_EXPECTED_PARTICIPANTS = 5
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN = 0
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX = 100
EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL = 10
SHOULD_PEER_REASK = 0
RECORDS_TO_ACQUIRE_MIN = 1
RECORDS_TO_ACQUIRE_MAX = 4
QUERIES_PER_EXPERIMENT = 200
ALTURISTS_MAX = 5
ALTURISTS_MIN = 0
ALTURISTS_INTERVAL = 1

output_filename = "theoretical_data.txt"

def ph_probability_mode():
    with open(output_filename,'w',encoding='utf-8') as outfile:
        for RECS_TO_GET in range(RECORDS_TO_ACQUIRE_MIN,RECORDS_TO_ACQUIRE_MAX+1):
            for ANS_PROB in range(EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN,EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX+1,EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL):
                probability_no_answer = pow( ( 1.0 - (float(ANS_PROB) / 100.0) ) , RECS_TO_GET )
                result = 1.0 - probability_no_answer
                outfile.write(f"{RECS_TO_GET} {ANS_PROB} {result}\n")

def ph_deterministic_mode():
    with open(output_filename,'w',encoding='utf-8') as outfile:
        for RECS_TO_GET in range(RECORDS_TO_ACQUIRE_MIN,RECORDS_TO_ACQUIRE_MAX+1):
            for ALTURISTS in range(ALTURISTS_MIN,ALTURISTS_MAX+1,ALTURISTS_INTERVAL):
                result = det_calc(RECS_TO_GET,ALTURISTS)
                outfile.write(f"{RECS_TO_GET} {ALTURISTS} {result}\n")

def sp_mal(N,D,M):
    M = M - 1 # removing one of the malicious guys
    N = N - 1 # removing one guy from the total
    peer_miss_prob = 1.0
    for i in range(0,D):
        peer_miss_prob = float(peer_miss_prob) * ( float(M) / float(N) )
        M = M-1
        N = N-1
    peer_hit_prob = 1.0 - peer_miss_prob
    return peer_hit_prob

def sp_alt(N,D,M):
    # M = M - 1 # we are not removing a malicious because this is an alturist
    N = N-1 # removing one guy from the total
    peer_miss_prob = 1.0
    for i in range(0,D):
        peer_miss_prob = float(peer_miss_prob) * (float(M) / float(N))
        M = M - 1
        N = N - 1
    peer_hit_prob = 1.0 - peer_miss_prob
    return peer_hit_prob

def res_for_mal(N,D,M):
    return ( (float(M) / float(N) ) * sp_mal(N,D,M) )

def res_for_alt(N,D,M):
    return (float(N-M) / float(N) ) * sp_alt(N,D,M)

def det_calc(RECS_TO_GET,ALTURISTS):
    N = EXPERIMENT_START_EXPECTED_PARTICIPANTS
    D = RECS_TO_GET
    M = N-ALTURISTS
    result_for_malicious = res_for_mal(N,D,M)
    result_for_alturists = res_for_alt(N,D,M)
    result = result_for_malicious + result_for_alturists
    return result

def main():
    if "ph_prob" in sys.argv: 
        ph_probability_mode()
    elif "ph_deter" in sys.argv:
        ph_deterministic_mode()
    else:
        print("No such option. Options: ph_prob or ph_deter")
        return

if __name__ == "__main__":
    main()
