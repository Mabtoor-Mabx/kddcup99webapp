import streamlit as st
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Load the trained model
model_filename = 'kddcup99ann.pkl'
model = joblib.load(model_filename)

# Load label encoders
label_encoders = joblib.load('label_encoders.pkl')  # Assuming you have saved the label encoders

# Mapping for human-readable outcome labels
outcome_mapping = {
    "normal": "Normal",
    "buffer_overflow": "Buffer Overflow",
    "loadmodule": "Load Module",
    "perl": "Perl",
    "neptune": "Neptune",
    "smurf": "Smurf",
    "guess_passwd": "Guess Passwd",
    "pod": "Pod",
    "teardrop": "Teardrop",
    "portsweep": "Port Sweep",
    "ipsweep": "IP Sweep",
    "land": "Land",
    "ftp_write": "Ftp Write",
    "back": "Back",
    "imap": "Imap",
    "satan": "Satan",
    "phf": "PHF",
    "nmap": "Nmap",
    "multihop": "Multihop",
    "warezmaster": "Warez Master",
    "warezclient": "Warez Client",
    "spy": "Spy",
    "rootkit": "Root Kit"
}

# Function to preprocess input data
def preprocess_input(data):
    categorical_features = ["protocol_type", "service", "flag"]
    
    for feature in categorical_features:
        le = label_encoders[feature]
        data[feature] = le.transform(data[feature])
    
    scaler = MinMaxScaler()
    data[data.columns] = scaler.fit_transform(data)
    
    return data

def main():
    st.markdown("<h1 style='text-align: center;'>KDD Cup 1999 Data</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Computer network intrusion detection</p>", unsafe_allow_html=True)
    
    st.subheader('About Dataset')
    st.markdown("<p style='text-align: justify;'>This is the data set used for The Third International Knowledge Discovery and Data Mining Tools Competition, which was held in conjunction with KDD-99 The Fifth International Conference on Knowledge Discovery and Data Mining. The competition task was to build a network intrusion detector, a predictive model capable of distinguishing between bad'' connections, called intrusions or attacks, andgood'' normal connections. This database contains a standard set of data to be audited, which includes a wide variety of intrusions simulated in a military network environment. Data</p>", unsafe_allow_html=True)

    # Input form
    st.subheader("Input Features")
    src_bytes = st.number_input("Source Bytes", min_value=0)
    count = st.number_input("Count", min_value=0)
    serror_rate = st.number_input("Serror Rate", min_value=0.0, max_value=1.0, step=0.01)
    protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
    service = st.selectbox("Service", ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp',
       'eco_i', 'ntp_u', 'ecr_i', 'other', 'private', 'pop_3', 'ftp_data',
       'rje', 'time', 'mtp', 'link', 'remote_job', 'gopher', 'ssh',
       'name', 'whois', 'domain', 'login', 'imap4', 'daytime', 'ctf',
       'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
       'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard',
       'systat', 'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2',
       'sunrpc', 'uucp_path', 'netbios_ns', 'netbios_ssn', 'netbios_dgm',
       'sql_net', 'vmnet', 'bgp', 'Z39_50', 'ldap', 'netstat', 'urh_i',
       'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'])  
    flag = st.selectbox("Flag", ['SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0',
       'OTH', 'SH'])  
    dst_host_srv_count = st.number_input("Destination Host Service Count", min_value=0)

    input_data = pd.DataFrame({
        "src_bytes": [src_bytes],
        "count": [count],
        "serror_rate": [serror_rate],
        "protocol_type": [protocol_type],
        "service": [service],
        "flag": [flag],
        "dst_host_srv_count": [dst_host_srv_count]
    })

    # Preprocess input
    input_data = preprocess_input(input_data)

    if st.button("Predict"):
        prediction = model.predict(input_data)
        predicted_class = prediction[0]

        if predicted_class in outcome_mapping:
            outcome_label = outcome_mapping[predicted_class]
            # st.write("Predicted Outcome:", outcome_label)
            # Display the predicted result
            st.subheader("Prediction Result")
            st.success(f"🎉 The predicted outcome is {outcome_label}.")
        else:
            st.error("Unable to determine predicted outcome.")

if __name__ == "__main__":
    main()
