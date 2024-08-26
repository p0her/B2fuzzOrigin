# RFCOMM STATE
RFCOMM_CLOSED_STATE = 0X01
RFCOMM_TERM_WAIT_SEC_CHECK_STATE = 0X02
RFCOMM_ORIG_WAIT_SEC_CHECK_STATE = 0X03
RFCOMM_SABM_WAIT_UA_STATE = 0X04
RFCOMM_OPENED_STATE = 0X05
RFCOMM_DISC_WAIT_UA_STATE = 0X06

# RFCOMM EVENTS
#CLOSE
#UA
#DM
#UIH
#DISC
#SABME

def state2str(state):
    if state == RFCOMM_CLOSED_STATE:
        return "closed_state"
    elif state == RFCOMM_TERM_WAIT_SEC_CHECK_STATE:
        return "term_wait_sec_check_state"
    elif state == RFCOMM_ORIG_WAIT_SEC_CHECK_STATE:
        return "orig_wait_sec_check_state"
    elif state == RFCOMM_SABM_WAIT_UA_STATE:
        return "sabm_wait_ua_state"
    elif state == RFCOMM_OPENED_STATE:
        return "opened_state"
    elif state == RFCOMM_DISC_WAIT_UA_STATE:
        return "disc_wait_ua_state"
    else:
        print(f"state name : {state}")
        assert False, "Exception state exists"