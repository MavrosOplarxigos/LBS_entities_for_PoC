EXPERIMENT_START_EXPECTED_PARTICIPANTS = 5
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN = 0
EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX = 100
EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL = 10
SHOULD_PEER_REASK = 0
RECORDS_TO_ACQUIRE_MIN = 1
RECORDS_TO_ACQUIRE_MAX = 4
QUERIES_PER_EXPERIMENT = 200

def probability_mode():
    for RECS_TO_GET in range(RECORDS_TO_ACQUIRE_MIN,RECORDS_TO_ACQUIRE_MAX+1):
        for ANS_PROB in range(EXPERIMENT_ANSWER_PROBABILITY_PCENT_MIN,EXPERIMENT_ANSWER_PROBABILITY_PCENT_MAX+1,EXPERIMENT_ANSWER_PROBABILITY_PCENT_INTERVAL):
            probability_no_answer = pow( ( 1.0 - (float(ANS_PROB) / 100.0) ) , RECS_TO_GET )
            result = 1.0 - probability_no_answer
            print(f"{RECS_TO_GET} {ANS_PROB} {result}")

probability_mode()
