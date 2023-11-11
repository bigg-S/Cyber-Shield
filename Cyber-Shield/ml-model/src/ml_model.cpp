#define NOMINMAX

#include "ml_model.h"

namespace PacketAnalyzer
{

	KNN::KNN(int val)
	{
		k = val;
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::KNN()
	{
		k = 3; // Default value for k
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::~KNN()
	{
		// Cleaning up
	}

	template<class Archive>
	void KNN::serialize(Archive& ar, const unsigned int version)
	{
		ar& k;
		ar& neighbors;
		ar& trainingData;
		ar& testData;
		ar& validationData;
	}

	// save KNN instance
	void KNN::SaveKNN(std::string& fileName)
	{
		std::ofstream ofs(fileName);
		boost::archive::text_oarchive oa(ofs);
		oa << *this;
	}

	// load the KNN instace
	void KNN::LoadKNN(std::string& fileName)
	{
		std::ifstream ifs(fileName);
		boost::archive::text_iarchive ia(ifs);
		ia >> *this;
	}

	void KNN::FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint)
	{
		neighbors = std::make_shared<std::vector<std::shared_ptr<DataCollection::Data>>>();
		double min = std::numeric_limits<double>::max();

		for (int i = 0; i < k; i++) {
			int index = -1;
			for (int j = 0; j < trainingData->size(); j++) {
				double distance = CalculateDistance(queryPoint, trainingData->at(j), DistanceMetric::EUCLID);
				trainingData->at(j)->SetDistance(distance);

				if (distance < min) {
					min = distance;
					index = j;
				}
			}

			if (index != -1) {
				neighbors->push_back(trainingData->at(index));
				min = std::numeric_limits<double>::max();
			}
		}
	}

	void KNN::SetTrainingData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		trainingData = vect;
	}

	void KNN::SetTestData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		testData = vect;
	}

	void KNN::SetValidationData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		validationData = vect;
	}

	void KNN::SetK(int val) // change k without reloading the data
	{
		k = val;
	}

	std::string KNN::Predict() // return predicted class
	{
		std::map<std::string, int> classFreq;
		for (int i = 0; i < neighbors->size(); i++)
		{
			if (classFreq.find(neighbors->at(i)->GetLabel()) == classFreq.end())
			{
				classFreq[neighbors->at(i)->GetLabel()] = 1;
			}
			else
			{
				classFreq[neighbors->at(i)->GetLabel()]++;
			}
		}

		std::string best;
		int max = 0;

		for (auto kv : classFreq)
		{
			if (kv.second > max)
			{
				max = kv.second;
				best = kv.first;
			}
		}
		neighbors->clear();
		return best;
	}

	double KNN::CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input, DistanceMetric metric)
	{
		double distance = 0.0;
		if (queryPoint->GetFeatureVectorSize() != input->GetFeatureVectorSize())
		{
			std::cerr<<"Error: Vector Size mismatch\n";
			exit(1);
		}

		for (unsigned i = 0; i < queryPoint->GetFeatureVectorSize(); i++)
		{
			if (metric == DistanceMetric::EUCLID)
			{
				distance += pow(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i), 2);
			}
			else if(metric == DistanceMetric::MANHATTAN)
			{
				distance += abs(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i));
			}
		}

		if (metric == DistanceMetric::EUCLID)
		{
			return sqrt(distance);
		}
		else
		{
			return distance;
		}
		
	}

	const std::vector<std::string>& KNN::GetTrueLabels() const
	{
		return trueLabels;
	}

	const std::vector<std::string>& KNN::GetPredictedLabels() const
	{
		return predictedLabels;
	}

	double KNN::ValidatePerformance()
	{
		double currentPerformance = 0;
		int count = 0;
		int dataIndex = 0;

		for (std::shared_ptr<DataCollection::Data> queryPoint : *validationData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
			dataIndex++;
			//printf("Current Performance = %.3f %%\n", ((double)count * 100.0 / ((double)dataIndex)));
		}
		currentPerformance = ((double)count * 100) / ((double)validationData->size());
		printf("Validation performance for k = %d = %.3f %%\n", k, ((double)count * 100.0 / ((double)validationData->size())));
		return currentPerformance;
	}

	double KNN::TestPerformance()
	{
		// Log start of testing
		std::cout << "Starting performance testing" << std::endl;

		double accuracy = 0.0;
		double precision = 0.0;
		double recall = 0.0;
		double f1Score = 0.0;
		std::vector<std::vector<int>> confusionMatrix;

		double currentPerformance = 0.0;
		int count = 0;
		
		// clear the lists to store the true predicted labels
		trueLabels.clear();
		predictedLabels.clear();

		for (std::shared_ptr<DataCollection::Data> queryPoint: *testData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();

			trueLabels.push_back(queryPoint->GetLabel());
			predictedLabels.push_back(prediction);
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
		}
		accuracy = static_cast<double>(count) / testData->size();

		currentPerformance = ((double)count * 100) / ((double)testData->size());
		printf("Test performance = %.3f %%\n", currentPerformance);

		// log accuracy
		std::cout << "Accuracy: " << accuracy * 100 <<  std::endl;

		// Calculate and log precision
		precision = CalculatePrecision(testData);
		std::cout << "Precision: " << precision * 100 << std::endl;

		// Calculate and log recall
		recall = CalculateRecall(testData);
		std::cout << "Recall: " << recall * 100 << std::endl;

		// Calculate and log F1 score
		f1Score = CalculateF1Score(testData);
		std::cout << "F1 Score: " << f1Score << std::endl;

		// Calculate and log confusion matrix
		CalculateConfusionMatrix(testData, confusionMatrix);
		std::cout << "Confusion matrix:" << std::endl;
		for (auto& row : confusionMatrix) 
		{
			for (auto count : row) 
			{
				std::cout << count << " ";
			}
			std::cout << std::endl;
		}

		// Log end of testing
		std::cout << "Finished performance testing" << std::endl;

		return currentPerformance;
	}

	// Calculate precision
	double KNN::CalculatePrecision(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data) {
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		int truePositives = 0;
		int falsePositives = 0;

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "anomaly") 
			{
				truePositives++;
			}
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "normal") 
			{
				falsePositives++;
			}
		}

		if (truePositives + falsePositives == 0) 
		{
			return 0.0;
		}

		return static_cast<double>(truePositives) / (truePositives + falsePositives);
	}

	// Calculate recall
	double KNN::CalculateRecall(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data) {
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		int truePositives = 0;
		int falseNegatives = 0;

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "anomaly") 
			{
				truePositives++;
			}
			if (prediction == "normal" && data->at(i)->GetLabel() == "anomaly") 
			{
				falseNegatives++;
			}
		}

		if (truePositives + falseNegatives == 0) 
		{
			return 0.0;
		}

		return static_cast<double>(truePositives) / (truePositives + falseNegatives);
	}

	// Calculate F1-score
	double KNN::CalculateF1Score(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data)
	{
		if (!data || !data->size())
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		double precision = CalculatePrecision(data);
		double recall = CalculateRecall(data);

		if (precision + recall == 0) 
		{
			return 0.0;
		}

		return 2.0 * (precision * recall) / (precision + recall);
	}

	// Calculate confusion matrix
	void KNN::CalculateConfusionMatrix(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data, std::vector<std::vector<int>>& confusionMatrix) 
	{
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return;
		}

		confusionMatrix = std::vector<std::vector<int>>(2, std::vector<int>(2, 0));

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (data->at(i)->GetLabel() == "normal") 
			{
				if (prediction == "normal") 
				{
					confusionMatrix[0][0]++; // True negatives
				}
				else 
				{
					confusionMatrix[0][1]++; // False positives
				}
			}
			else 
			{
				if (prediction == "anomaly") 
				{
					confusionMatrix[1][1]++; // True positives
				}
				else 
				{
					confusionMatrix[1][0]++; // False negatives
				}
			}
		}
	}

	// Cross-validation
	double KNN::CrossValidation(int numFolds) {
		if (!validationData) 
		{
			std::cerr << "Error: Validation data not set." << std::endl;
			return 0.0;
		}

		size_t foldSize = validationData->size() / numFolds;
		double totalAccuracy = 0.0;

		for (int fold = 0; fold < numFolds; fold++) 
		{
			std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>
				validationFold(new std::vector<std::shared_ptr<DataCollection::Data>>());
			std::shared_ptr<std::vector<std::string>> labelsFold(new std::vector<std::string>());

			// Split data into folds
			for (size_t i = 0; i < validationData->size(); i++) 
			{
				if (i >= fold * foldSize && i < (fold + 1) * foldSize) 
				{
					validationFold->push_back(validationData->at(i));
					labelsFold->push_back(validationData->at(i)->GetLabel());
				}
			}

			SetValidationData(validationFold);
			double accuracy = ValidatePerformance();
			totalAccuracy += accuracy;
		}

		// Average accuracy over folds
		return totalAccuracy / numFolds;
	}
}