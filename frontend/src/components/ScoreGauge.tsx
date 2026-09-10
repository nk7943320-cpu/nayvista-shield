import React from 'react';

interface ScoreGaugeProps {
  score: number | null;
  grade: string;
  riskLevel: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, grade, riskLevel }) => {
  const isScoreAvailable = score !== null && score !== undefined;
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = isScoreAvailable ? circumference - (score / 100) * circumference : circumference;

  const getColor = (s: number | null) => {
    if (s === null || s === undefined) return '#FFD400';
    if (s >= 80) return '#84CC16'; // low risk / high score: lime/green
    if (s >= 65) return '#FFD400'; // medium: yellow
    if (s >= 50) return '#FF8800'; // high: orange
    return '#FF4444'; // critical: red
  };

  const color = getColor(score);

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative flex items-center justify-center w-36 h-36">
        <svg className="w-full h-full transform -rotate-90">
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke="#1A180C"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke={color}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="square"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold text-[#FFF8DB] font-mono leading-none">
            {isScoreAvailable ? score : 'N/A'}
          </span>
          {isScoreAvailable ? (
            <span className="text-[10px] text-[#A89F82] font-bold uppercase mt-1 font-mono">/ 100</span>
          ) : (
            <span className="text-[9px] text-amber-400 font-bold uppercase mt-1 font-mono">LIMITED</span>
          )}
        </div>
      </div>

      <div className="mt-4 text-center space-y-1.5 font-mono">
        <div className="flex items-center justify-center space-x-2">
          <span className="text-[11px] text-[#7A7256] uppercase font-bold">GRADE</span>
          <span
            className="px-2 py-0.5 border text-xs font-bold uppercase"
            style={{ backgroundColor: `${color}15`, borderColor: color, color }}
          >
            {grade || 'N/A'}
          </span>
        </div>
        <div className="text-[11px] text-[#C7B988] font-bold">
          RISK: <span className="uppercase" style={{ color }}>{riskLevel || (isScoreAvailable ? 'LOW' : 'LIMITED')}</span>
        </div>
      </div>
    </div>
  );
};

