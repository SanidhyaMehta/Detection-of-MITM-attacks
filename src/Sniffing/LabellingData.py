import pandas as pd


df = pd.read_csv("cleaned_packets.csv")  # Replace with your filename


required_cols = ['Destination Port', 'TTL', 'Length', 'Flags']
for col in required_cols:
    if col not in df.columns:
        raise ValueError(f"Missing required column: {col}")


df['Flags'] = df['Flags'].fillna(0).astype(int)

# Defining labeling logic
def label_packet(row):
    if (row['Destination Port'] > 50000 or
        row['TTL'] < 30 or
        row['Length'] > 1000 or
        row['Flags'] == 0):
        return 1  # Suspicious / Attack
    return 0  # Normal

# Applying logic to each row
df['Label'] = df.apply(label_packet, axis=1)


df.to_csv("labeled_packet_data.csv", index=False)


