import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from core_implementation import MusicRevenueAnalyzer, normalize_revenue, encode_genre, encode_season


class MusicRevenueVisualizer:
    """
    암호화된 음악 수익 데이터에 대한 시각화 도구
    복호화된 통계 결과를 시각적으로 표현합니다.
    """

    def __init__(self, analyzer):
        """
        시각화 도구를 초기화합니다.

        Args:
            analyzer: MusicRevenueAnalyzer 인스턴스
        """
        self.analyzer = analyzer
        self.quarters = ["Q1", "Q2", "Q3", "Q4"]
        self.genres = ["Pop", "Rock", "Hip-Hop",
                       "R&B", "EDM", "Classical", "Jazz", "Folk"]

    def plot_revenue_comparison(self, personal_data, average_data, title="수익 비교"):
        """
        개인 수익과 평균 수익을 비교하는 그래프를 생성합니다.

        Args:
            personal_data: 개인 수익 데이터 (복호화됨)
            average_data: 평균 수익 데이터 (복호화됨)
            title: 그래프 제목
        """
        # 분기별 데이터만 추출 (처음 4개 항목)
        personal = personal_data[:4]
        average = average_data[:4]

        x = np.arange(len(self.quarters))
        width = 0.35

        fig, ax = plt.subplots(figsize=(10, 6))
        rects1 = ax.bar(x - width/2, personal, width, label='내 수익')
        rects2 = ax.bar(x + width/2, average, width, label='평균 수익')

        # 그래프 설정
        ax.set_title(title, fontsize=16)
        ax.set_xlabel('분기', fontsize=12)
        ax.set_ylabel('수익 (만원)', fontsize=12)
        ax.set_xticks(x)
        ax.set_xticklabels(self.quarters)
        ax.legend()

        # 값 표시
        def autolabel(rects):
            for rect in rects:
                height = rect.get_height()
                ax.annotate(f'{height:.1f}',
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom')

        autolabel(rects1)
        autolabel(rects2)

        plt.tight_layout()
        return fig

    def plot_genre_comparison(self, personal_genre_index, all_genre_averages, title="장르별 평균 수익"):
        """
        장르별 평균 수익을 비교하는 그래프를 생성합니다.

        Args:
            personal_genre_index: 개인 장르 인덱스
            all_genre_averages: 모든 장르의 평균 수익 (복호화됨)
            title: 그래프 제목
        """
        # 모든 장르의 평균 (각 장르마다 4개 분기 평균)
        genres_data = []
        for i, genre in enumerate(self.genres):
            if i < len(all_genre_averages):
                # 각 장르의 4개 분기 평균
                genres_data.append(np.mean(all_genre_averages[i][:4]))
            else:
                genres_data.append(0)  # 데이터 없음

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.bar(self.genres, genres_data)

        # 개인 장르 하이라이트
        if 0 <= personal_genre_index < len(self.genres):
            bars[personal_genre_index].set_color('orange')

        # 그래프 설정
        ax.set_title(title, fontsize=16)
        ax.set_xlabel('장르', fontsize=12)
        ax.set_ylabel('평균 수익 (만원)', fontsize=12)

        # 값 표시
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom')

        plt.tight_layout()
        return fig

    def plot_seasonal_trends(self, all_data, title="계절별 트렌드"):
        """
        계절별 트렌드를 시각화합니다.

        Args:
            all_data: 모든 계절의 평균 데이터 딕셔너리 (복호화됨)
            title: 그래프 제목
        """
        seasons = list(all_data.keys())
        averages = [np.mean(all_data[season]) for season in seasons]

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(seasons, averages, 'o-', linewidth=2, markersize=10)

        # 그래프 설정
        ax.set_title(title, fontsize=16)
        ax.set_xlabel('계절', fontsize=12)
        ax.set_ylabel('평균 수익 (만원)', fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.7)

        # 값 표시
        for i, v in enumerate(averages):
            ax.annotate(f'{v:.1f}',
                        xy=(i, v),
                        xytext=(0, 10),
                        textcoords="offset points",
                        ha='center')

        plt.tight_layout()
        return fig

    def plot_percentile_position(self, personal_value, percentiles, title="업계 내 위치"):
        """
        개인 수익의 백분위 위치를 시각화합니다.

        Args:
            personal_value: 개인 평균 수익
            percentiles: 백분위수별 값 딕셔너리 (예: {10: 값, 25: 값, ...})
            title: 그래프 제목
        """
        fig, ax = plt.subplots(figsize=(10, 3))

        # 백분위수 위치
        percentile_positions = list(percentiles.keys())
        percentile_values = list(percentiles.values())

        # 개인 위치 찾기
        personal_percentile = 0
        for i, p in enumerate(percentile_positions):
            if personal_value >= percentile_values[i]:
                personal_percentile = p

        # 그래프 생성
        ax.axhline(y=0, color='black', linestyle='-', alpha=0.3)

        # 백분위수 표시
        for i, (p, v) in enumerate(percentiles.items()):
            ax.scatter(v, 0, color='blue', s=100, zorder=2)
            ax.annotate(f'{p}%',
                        xy=(v, 0),
                        xytext=(0, 10),
                        textcoords="offset points",
                        ha='center')

        # 개인 위치 표시
        ax.scatter(personal_value, 0, color='red', s=150, zorder=3)
        ax.annotate('내 수익',
                    xy=(personal_value, 0),
                    xytext=(0, -25),
                    textcoords="offset points",
                    ha='center',
                    color='red',
                    fontweight='bold')

        # 그래프 설정
        ax.set_title(title, fontsize=16)
        ax.set_xlabel('수익 (만원)', fontsize=12)
        ax.set_yticks([])

        # 상위 % 표시
        percentile_text = f"상위 약 {100-personal_percentile}%"
        ax.annotate(percentile_text,
                    xy=(0.5, 0.75),
                    xycoords='axes fraction',
                    fontsize=14,
                    fontweight='bold',
                    ha='center',
                    bbox=dict(boxstyle="round,pad=0.3", fc="yellow", alpha=0.3))

        plt.tight_layout()
        return fig

# UI의 기본적인 흐름을 시뮬레이션하는 함수


def run_demo_ui():
    """
    데모 UI 흐름을 시뮬레이션합니다.
    실제 구현에서는 웹 또는 데스크톱 UI로 대체됩니다.
    """
    # 분석기 초기화
    analyzer = MusicRevenueAnalyzer()
    visualizer = MusicRevenueVisualizer(analyzer)

    print("\n===== 음악 창작자 익명 수익 분석 플랫폼 =====")

    # 사용자 입력 시뮬레이션
    print("\n[1] 개인 정보 입력:")
    genre = "pop"
    experience = 3
    print(f"- 장르: {genre}")
    print(f"- 경력(년): {experience}")

    # 수익 데이터 시뮬레이션
    print("\n[2] 분기별 수익 입력 (만원):")
    quarterly_revenue = [150, 200, 180, 250]
    for i, rev in enumerate(quarterly_revenue):
        print(f"- Q{i+1}: {rev}")

    # 데이터 암호화 (실제로는 클라이언트 측에서 수행)
    print("\n[3] 데이터 암호화 및 전송 중...")
    metadata = {
        "genre": genre,
        "experience": experience
    }
    encrypted_data = analyzer.encrypt_revenue_data(quarterly_revenue, metadata)
    print("- 암호화 완료 및 서버 전송 완료")

    # 서버 측 처리 시뮬레이션
    print("\n[4] 서버에서 통계 분석 수행 중...")

    # 다른 창작자 데이터 시뮬레이션 (실제로는 서버에 이미 저장되어 있음)
    other_creators = [
        {"revenue": [130, 150, 160, 170], "metadata": {
            "genre": "pop", "experience": 2}},
        {"revenue": [200, 220, 210, 230], "metadata": {
            "genre": "pop", "experience": 5}},
        {"revenue": [100, 120, 110, 130], "metadata": {
            "genre": "rock", "experience": 1}},
        {"revenue": [180, 190, 200, 210], "metadata": {
            "genre": "hiphop", "experience": 4}}
    ]

    all_encrypted_data = [encrypted_data]
    for creator in other_creators:
        all_encrypted_data.append(
            analyzer.encrypt_revenue_data(
                creator["revenue"], creator["metadata"])
        )

    # 각종 통계 계산
    pop_average = analyzer.calculate_average(
        all_encrypted_data, {"genre": "pop"})
    rock_average = analyzer.calculate_average(
        all_encrypted_data, {"genre": "rock"})
    hiphop_average = analyzer.calculate_average(
        all_encrypted_data, {"genre": "hiphop"})

    # 결과 복호화 (실제로는 클라이언트 측에서 수행)
    print("\n[5] 결과 복호화 및 시각화 중...")

    # 복호화 결과 시뮬레이션
    decrypted_personal = quarterly_revenue
    # 실제로는 analyzer.decrypt_result(pop_average)
    decrypted_pop_avg = [160.0, 190.0, 183.3, 216.7]

    genre_averages = [
        decrypted_pop_avg,
        [100.0, 120.0, 110.0, 130.0],  # Rock
        [180.0, 190.0, 200.0, 210.0]  # Hip-hop
    ]

    # 백분위수 데이터 시뮬레이션 (실제로는 동형 암호화로 계산됨)
    percentiles = {
        10: 110.0,
        25: 130.0,
        50: 160.0,
        75: 190.0,
        90: 220.0
    }

    # 시각화 및 결과 표시
    print("\n[6] 분석 결과:")

    # 시각화 1: 개인 vs 평균 비교
    print("\n-- 분기별 수익 비교 --")
    fig1 = visualizer.plot_revenue_comparison(
        decrypted_personal, decrypted_pop_avg, "내 수익 vs 장르 평균")
    plt.savefig("revenue_comparison.png")
    print("- 내 수익이 장르 평균보다 Q1에서는 낮지만, Q4에서는 높습니다.")

    # 시각화 2: 장르별 비교
    print("\n-- 장르별 평균 수익 비교 --")
    fig2 = visualizer.plot_genre_comparison(0, genre_averages, "장르별 평균 수익")
    plt.savefig("genre_comparison.png")
    print("- 팝 장르는 Hip-hop보다 평균 수익이 낮지만, Rock보다는 높습니다.")

    # 시각화 3: 백분위 위치
    print("\n-- 업계 내 위치 --")
    personal_avg = np.mean(decrypted_personal)
    fig3 = visualizer.plot_percentile_position(
        personal_avg, percentiles, "업계 내 내 위치")
    plt.savefig("percentile_position.png")
    print(f"- 평균 수익 {personal_avg:.1f}만원은 업계 상위 약 25%에 속합니다.")

    # 시각화 4: 계절별 트렌드
    print("\n-- 계절별 트렌드 --")
    seasonal_data = {
        "봄(Q1)": [130, 100, 180, 150],
        "여름(Q2)": [150, 120, 190, 200],
        "가을(Q3)": [160, 110, 200, 180],
        "겨울(Q4)": [170, 130, 210, 250]
    }
    fig4 = visualizer.plot_seasonal_trends(seasonal_data, "계절별 수익 트렌드")
    plt.savefig("seasonal_trends.png")
    print("- 겨울 시즌(Q4)에 가장 높은 수익이 발생합니다.")

    print("\n\n===== 분석 완료 =====")
    print("모든 분석은 원본 데이터를 노출하지 않고 암호화된 상태에서 이루어졌습니다.")


if __name__ == "__main__":
    run_demo_ui()
