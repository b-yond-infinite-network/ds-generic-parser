import numpy as np
import pandas as pd
from sklearn.metrics import silhouette_samples


def cluster(model, clusterin_data):
    if len(clusterin_data) < 2:
        return [1], [1], 1
    clusters = model.fit_predict(clusterin_data)
    silhouette = silhouette_samples(clusterin_data, clusters)
    return clusters, silhouette


def score_fun(df, clusters, silhouette, label):
    all_df, clusters_df, silhouette_mean = result_fun(df, clusters, silhouette)
    if label is None:
        return all_df, clusters_df, 0, 0, silhouette_mean

    # Add most occuring label in cluster: name, count, and percentage of the cluster 
    df3 = all_df.groupby(["Cluster", label]).size().sort_values().groupby(level=0).tail(1).reset_index(level=label, name='Max_Label_Count')
    clusters_df = clusters_df.join(df3, on='Cluster').rename(columns={label: 'Max_Label'})
    clusters_df['Percent'] = clusters_df['Max_Label_Count'] / clusters_df['Cluster_Size']

    score = clusters_df['Max_Label_Count'].sum() / clusters_df['Cluster_Size'].sum()
    return all_df, clusters_df, score, clusters_df['Percent'].mean(), silhouette_mean


def result_fun(df, clusters, silhouette):
    clusters = pd.Series(clusters, name='Cluster')
    silhouette = pd.Series(silhouette, name='Silhouette')
    all_df = pd.concat([clusters, silhouette, df], axis=1)
    # Group by clusters and add cluster size ans cluster silhouette mean
    # clusters_df = all_df.groupby(["Cluster"]).size().reset_index(name='Cluster_Size')
    clusters_df = all_df.groupby('Cluster').agg(Cluster_Size=('Cluster', 'size'), Silhouette_Mean=('Silhouette', 'mean')).reset_index()
    return all_df, clusters_df, silhouette.mean()


def transform_data(idf, replace):
    if replace is not None:
        return idf.fillna(replace)
    return idf


def min_max_normalization(value, x, y, xnew, ynew):
    # Transform value in range (x to y) into some interval (xnew to ynew)
    return xnew + (ynew - xnew) * (value - x) / (y - x)


def optimal_cluster_num(idf):
    row_count = len(idf)
    if row_count <= 2:
        return row_count
    elif row_count <= 10:
        return int(min_max_normalization(row_count, 2, 10, 2, 5))
    elif row_count <= 100:
        return int(min_max_normalization(row_count, 10, 100, 5, 15))
    elif row_count <= 200:
        return int(min_max_normalization(row_count, 100, 200, 15, 20))
    elif row_count <= 400:
        return int(min_max_normalization(row_count, 200, 400, 20, 30))
    elif row_count <= 1000:
        return int(min_max_normalization(row_count, 400, 1000, 30, 75))
    elif row_count <= 6000:
        return int(min_max_normalization(row_count, 1000, 6000, 75, 150))
    return 150


def one_hot_encoder(idf):
    unique_values = np.unique(idf.astype(str).values).tolist()
    if '*' in unique_values:
        unique_values.remove('*')

    data = []
    for row in idf.itertuples():
        values_set = set(row[1:len(row)])
        data.append([int(word in values_set) for word in unique_values])
    return pd.DataFrame(data=data, columns=unique_values)


def comapre_pcap_to_cluster(diff_df, pcap_name):
    pcap_df = diff_df[(diff_df['pcap'] == pcap_name)]
    pcap_cluster_num = pcap_df['Cluster'].values[0]

    diff_df = diff_df[diff_df['Cluster'] == pcap_cluster_num].reset_index(drop=True)
    diff_df = diff_df[[x for x in diff_df.columns if x in ['Cluster', 'Silhouette', 'pcap', 'Label'] or diff_df[x].mean() not in [0, 1]]]
    pcap_df = diff_df[(diff_df['pcap'] == pcap_name)].reset_index(drop=True)

    t = pcap_df.T
    t.columns = ['pcap']

    clusters_mean = diff_df[(diff_df['Cluster'] == pcap_cluster_num)].groupby("Cluster").mean().reset_index()  # & (diff_df['pcap'] != pcap_name)
    clusters_mean = clusters_mean.T
    t = t.join(clusters_mean)
    # pd.set_option('display.max_rows', None)
    t.columns = ['pcap', 'Average']
    t['diff'] = (t['pcap'] - t['Average']).abs()
    t = t.sort_values('diff', ascending=False)
    average_by_pcap = 1 - t['diff'].mean()
    result = t[t['pcap'] != t['Average']]
    return result, average_by_pcap


def new_score(diff_df):
    pcaps = diff_df['pcap'].values
    data = []
    for pcap in pcaps:
        result, average_by_pcap = comapre_pcap_to_cluster(diff_df, pcap)
        data.append(average_by_pcap)
    diff_df['New_Score'] = data
    return diff_df


# def comapre_pcap_to_pcap(diff_df, pcap_name, pcap_name2):
#     cluster_num = 48
#     # max_label = 'sip503-C-SBC-Unavailable'
#     max_label = clusters_df[clusters_df['Cluster']==cluster_num]['Max_Label'].values[0]
#     t= all_df[(all_df['Cluster']==cluster_num) & (all_df['Label'] != max_label)] #  & (clusters_df['Silhouette']<0.1) & (clusters_df['Label'] != 'success')]
#     t = t.head(1).T
#     clusters_mean = all_df[(all_df['Cluster']==cluster_num) & (all_df['Label'] == max_label)].groupby("Cluster").mean().reset_index()
#     clusters_mean = clusters_mean.T
#     t = t.join(clusters_mean)
#     # pd.set_option('display.max_rows', None)
#     t.columns = ['pcap', 'Average']
#     return t[t['pcap'] != t['Average']]


def cluster_info(idf, cluster_num):
    cluster_df = idf[idf['Cluster'] == cluster_num]
    clusters_mean = cluster_df[[x for x in cluster_df.columns if x in ['Cluster', 'Silhouette', 'pcap', 'Label'] or cluster_df[x].mean() not in [0, 1]]]
    clusters_mean = clusters_mean.groupby("Cluster").mean().reset_index()
    min_silouhete = cluster_df[cluster_df['Silhouette'] == cluster_df['Silhouette'].min()]
    max_silouhete = cluster_df[cluster_df['Silhouette'] == cluster_df['Silhouette'].max()]
    min_sim = cluster_df[cluster_df['New_Score'] == cluster_df['New_Score'].min()]
    max_sim = cluster_df[cluster_df['New_Score'] == cluster_df['New_Score'].max()]
    return clusters_mean.T, min_silouhete.T, max_silouhete.T, min_sim.T, max_sim.T
