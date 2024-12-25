import subprocess
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import os
import traceback

class LBNLAnalyzer:
    def __init__(self):
        self.config = {
            'anomaly_threshold': 1000,
            'start_date': '2004/10/04:20',
            'end_date': '2005/01/08:05',
            'bin_size': 60
        }
        
        self.anomaly_threshold = self.config['anomaly_threshold']
        self.start_date = self.config['start_date']
        self.end_date = self.config['end_date']
        self.bin_size = self.config['bin_size']
        
        self.output_dir = 'output'
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.watermark = ' '

    def fetch_tcp_data(self):
        print("\nFetching TCP traffic data...")
        
        verify_cmd = [
            'rwfilter',
            f'--start-date={self.start_date}',
            f'--end-date={self.end_date}',
            '--sensor=S0',
            '--type=all',
            '--proto=6',
            '--print-statistics'
        ]
        
        try:
            print("Verifying data access...")
            verify_result = subprocess.run(' '.join(verify_cmd), shell=True, capture_output=True, text=True)
            print(verify_result.stdout)
            
            cmd = [
                'rwfilter',
                f'--start-date={self.start_date}',
                f'--end-date={self.end_date}',
                '--sensor=S0',
                '--type=all',
                '--proto=6',
                '--pass=stdout',
                '|',
                'rwuniq',
                '--fields=sTime',
                '--values=packets,bytes',
                '--bin-time=60'
            ]
            
            print("Executing command:", ' '.join(cmd))
            result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True)
            
            if result.stdout:
                return self.parse_rwcount_output(result.stdout)
            else:
                print("No data received")
                return None
                
        except Exception as e:
            print(f"Error: {e}")
            return None

    def parse_rwcount_output(self, output):
        print("\nParsing output data...")
        records = []
        
        for line in output.split('\n'):
            if line and not line.startswith('#') and not 'sTime' in line:
                try:
                    parts = line.strip().split('|')
                    if len(parts) >= 2:
                        record = {
                            'timestamp': pd.to_datetime(parts[0].strip()),
                            'packets': int(float(parts[1].strip()) if len(parts) > 1 else 0)
                        }
                        if len(parts) > 2:
                            record['bytes'] = int(float(parts[2].strip()))
                        records.append(record)
                except:
                    continue
        
        if not records:
            return None
        
        df = pd.DataFrame(records)
        df = df.sort_values('timestamp')
        return df

    def classify_traffic(self, df):
        ranges = [
            (0, 600),
            (601, 6000),
            (6001, 60000),
            (60001, float('inf'))
        ]
        
        df['traffic_class'] = pd.cut(df['packets'], 
                                   bins=[r[0] for r in ranges] + [float('inf')],
                                   labels=['Low', 'Medium', 'High', 'Very High'])
        
        df['vfdt_class'] = pd.qcut(df['packets'], q=4, labels=['Q1', 'Q2', 'Q3', 'Q4'])
        
        return df

    def detect_anomalies(self, df):
        minute_threshold = self.anomaly_threshold * 60
        anomalies = df[df['packets'] > minute_threshold].copy()
        print(f"Found {len(anomalies)} anomalies")
        return anomalies

    def add_watermark(self, fig):
        fig.text(0.99, 0.01, self.watermark,
                fontsize=10, color='gray',
                ha='right', va='bottom',
                alpha=0.7,
                transform=fig.transFigure)

    def create_plots(self, df, anomalies):
        print("\nCreating visualization plots...")
        
        fig = plt.figure(figsize=(15, 8))
        plt.plot(df['timestamp'], df['packets'], label='Normal Traffic', color='blue', alpha=0.7)
        if not anomalies.empty:
            plt.scatter(anomalies['timestamp'], anomalies['packets'],
                       color='red', label='Anomalies', alpha=0.7, s=50)
        plt.title('TCP Traffic Analysis with Anomaly Detection', fontsize=14, pad=20)
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Packets per Minute', fontsize=12)
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        self.add_watermark(fig)
        plt.savefig(os.path.join(self.output_dir, 'traffic_timeline.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        fig = plt.figure(figsize=(15, 12))
        
        plt.subplot(2, 2, 1)
        class_counts = df['traffic_class'].value_counts()
        plt.bar(range(len(class_counts)), class_counts.values, color='skyblue')
        plt.xticks(range(len(class_counts)), class_counts.index, rotation=45)
        plt.title('Traffic Classification Distribution', fontsize=12)
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 2)
        vfdt_counts = df['vfdt_class'].value_counts()
        plt.pie(vfdt_counts.values, labels=vfdt_counts.index, autopct='%1.1f%%',
                colors=['lightblue', 'lightgreen', 'lightcoral', 'lightyellow'])
        plt.title('VFDT Classification Distribution', fontsize=12)
        
        plt.subplot(2, 2, 3)
        plt.hist(df['packets'], bins=50, alpha=0.7, color='lightgreen')
        plt.axvline(x=self.anomaly_threshold * 60, color='red',
                   linestyle='--', label='Anomaly Threshold')
        plt.title('Packet Distribution', fontsize=12)
        plt.xlabel('Packets per Minute')
        plt.ylabel('Frequency')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 4)
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day
        pivot = df.pivot_table(index='day', columns='hour',
                             values='packets', aggfunc='mean')
        im = plt.imshow(pivot, aspect='auto', cmap='YlOrRd')
        plt.colorbar(im)
        plt.title('Traffic Intensity Heatmap', fontsize=12)
        plt.xlabel('Hour of Day')
        plt.ylabel('Day of Month')
        
        plt.suptitle('TCP Traffic Analysis Results', fontsize=16, y=1.02)
        plt.tight_layout()
        self.add_watermark(fig)
        plt.savefig(os.path.join(self.output_dir, 'traffic_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        if not anomalies.empty:
            fig = plt.figure(figsize=(15, 6))
            anomaly_counts = anomalies.groupby(anomalies['timestamp'].dt.date).size()
            plt.bar(range(len(anomaly_counts)), anomaly_counts.values, color='red', alpha=0.7)
            plt.xticks(range(len(anomaly_counts)), 
                      [str(d) for d in anomaly_counts.index],
                      rotation=45)
            plt.title('Anomalies Distribution Over Time', fontsize=14, pad=20)
            plt.xlabel('Date', fontsize=12)
            plt.ylabel('Number of Anomalies', fontsize=12)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            self.add_watermark(fig)
            plt.savefig(os.path.join(self.output_dir, 'anomaly_distribution.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()

    def save_results(self, df, stats, anomalies):
        output_file = os.path.join(self.output_dir, 'analysis_results.txt')
        
        with open(output_file, 'w') as f:
            f.write("=== TCP Traffic Analysis Results ===\n\n")
            f.write(f"Analysis by: {self.watermark}\n\n")
            
            f.write("Overall Statistics:\n")
            for key, value in stats.items():
                f.write(f"{key}: {value:,.2f}\n")
            
            f.write("\nTraffic Classification Summary:\n")
            f.write(df['traffic_class'].value_counts().to_string())
            
            f.write("\n\nVFDT Classification Summary:\n")
            f.write(df['vfdt_class'].value_counts().to_string())
            
            if not anomalies.empty:
                f.write(f"\n\nAnomalies Detected: {len(anomalies)}\n")
                f.write("\nTop 5 Anomalous Periods:\n")
                f.write(anomalies.nlargest(5, 'packets').to_string())

    def analyze_tcp_traffic(self):
        df = self.fetch_tcp_data()
        if df is None or df.empty:
            print("Error: No data available")
            return None
        
        try:
            df = self.classify_traffic(df)
            anomalies = self.detect_anomalies(df)
            self.create_plots(df, anomalies)
            
            stats = {
                'total_packets': df['packets'].sum(),
                'total_bytes': df['bytes'].sum() if 'bytes' in df.columns else 0,
                'avg_packets_per_min': df['packets'].mean(),
                'max_packets_per_min': df['packets'].max(),
                'min_packets_per_min': df['packets'].min(),
                'std_dev_packets': df['packets'].std(),
                'total_minutes': len(df),
                'anomalies_detected': len(anomalies)
            }
            
            self.save_results(df, stats, anomalies)
            return stats
            
        except Exception as e:
            print(f"Error during analysis: {e}")
            return None

if __name__ == "__main__":
    print("=== LBNL TCP Traffic Analyzer ===")
    print(f"Analysis by: G23AI2029 Gowtham Ram")
    
    analyzer = LBNLAnalyzer()
    results = analyzer.analyze_tcp_traffic()
    
    if results:
        print("\nAnalysis complete! Check output directory for:")
        print("1. traffic_timeline.png - TCP traffic over time with anomalies")
        print("2. traffic_analysis.png - Classification and distribution analysis")
        print("3. anomaly_distribution.png - Anomaly patterns")
        print("4. analysis_results.txt - Detailed statistics and findings")
        
        print("\nKey findings:")
        for key, value in results.items():
            print(f"{key}: {value:,.2f}")
    else:
        print("\nAnalysis failed. Check the error messages above for details.")
