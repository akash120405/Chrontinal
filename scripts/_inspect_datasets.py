import pandas as pd
import os
import json

# Email label distributions
for f in ['CEAS_08.csv', 'Enron.csv', 'Ling.csv', 'Nazario.csv', 'Nigerian_Fraud.csv', 'SpamAssasin.csv']:
    fp = f'agents/Data/Latest_Dataset/11_Email/{f}'
    if os.path.exists(fp):
        df = pd.read_csv(fp, nrows=50000)
        print(f'{f}: {len(df)} rows, cols={df.columns.tolist()[:5]}')
        if 'label' in df.columns:
            print(f'  Labels: {df["label"].value_counts().to_dict()}')
        elif 'Label' in df.columns:
            print(f'  Labels: {df["Label"].value_counts().to_dict()}')
        print()

# AD label distribution
df = pd.read_csv('agents/Data/Latest_Dataset/04_Active_Directory/lanl_auth_ad.csv')
print(f'AD dataset: {len(df)} rows')
print(f'  Labels: {df["label"].value_counts().to_dict()}')
print()

# Stratus - total events across all files
sdir = 'agents/Data/Latest_Dataset/06_Cloud_AWS/stratus-detonation-logs'
total = 0
for f in os.listdir(sdir):
    if f.endswith('.json'):
        with open(os.path.join(sdir, f)) as fh:
            data = json.load(fh)
        if isinstance(data, list):
            total += len(data)
print(f'Stratus AWS attacks: {total} total events across {len(os.listdir(sdir))} files')
print()

# KDD
print('=== KDD ===')
cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
        'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
        'root_shell','su_attempted','num_root','num_file_creations','num_shells',
        'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
        'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
        'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
        'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
        'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
        'label','difficulty']
df = pd.read_csv('agents/Data/Latest_Dataset/10_IDS_IPS/KDDTest+.txt', header=None, names=cols, nrows=50000)
print(f'KDDTest+: {len(df)} rows')
print('  Label distribution:')
for lbl, cnt in df['label'].value_counts().head(10).items():
    print(f'    {lbl}: {cnt}')

# Apache
print()
print('=== APACHE ===')
df = pd.read_csv('agents/Data/Latest_Dataset/08_Web_Server/Loghub_Apache/Apache_2k.log_structured.csv', nrows=5)
print(f'Shape: {df.shape}')
print(f'Columns: {df.columns.tolist()}')
print(df.head(2).to_string())

# Cloud nineteenFeatures
print()
print('=== Cloud nineteenFeaturesDf ===')
df = pd.read_csv('agents/Data/Latest_Dataset/06_Cloud_AWS/nineteenFeaturesDf.csv', nrows=5)
print(f'Shape: {df.shape}')
print(f'Columns: {df.columns.tolist()}')
